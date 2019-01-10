<#
.SYNOPSIS
    Scans a given subnet for running hosts and open ports.

.DESCRIPTION
    This script will enumerate running hosts using a ping scan, and then check for the given open TCP and UDP ports.

.PARAMETER ip
    The IP/network address to scan.

.PARAMETER mask
    The subnet mask for the given network.

.PARAMETER tcp
    An array of TCP ports to scan.

.PARAMETER udp
    An array of UDP ports to scan.

.PARAMETER timeout
    The timeout in milliseconds for responses during UDP scanning (default: 1000).

.PARAMETER interval
    The sleep interval in milliseconds between UDP requests to prevent ICMP flooding (default: 1000).

.OUTPUTS
    An array of host objects. Each host object contains the following items:
        - host: the IP address of this host
        - ports: an array of port objects (containing port, type, and state properties)
        - up: True or False for whether the host was up

.NOTES
    Name: Net-Scan.ps1
    Author: Caleb Stewart
    DateCreated: 09Jan2019

    If ICMP packets are blocked on your network, this scan will not work. Hosts are only scanned if a ping is successful.

.LINK
    https://github.com/Caleb1994/PowershellScan

.EXAMPLE
    Net-Scan -ip 192.168.0.0 -mask 255.255.255.0 -tcp 80
    Scans for web servers on the local /24 subnet.
#>
param (
    [Parameter(Mandatory=$true)][IPAddress]$ip,
    [Parameter(Mandatory=$true)][IPAddress]$mask,
    [int[]]$tcp = @(),
    [int[]]$udp = @(),
    [int]$timeout = 1000,
    [int]$interval = 1000,
    [string]$data = "$(Get-Date)"
)

# The variable holding our results
$report = @()

# find start and end addresses
$start = [uint32]($ip.Address -band $mask.Address)
$end = ($start + ([uint32]((-bnot $mask.Address) -band [uint32]0xFFFFFFFFL)))

# Convert Endianness for loop if needed
if( [bitconverter]::IsLittleEndian ){
    $start = [bitconverter]::GetBytes($start)
    [array]::Reverse($start)
    $start = [bitconverter]::ToUInt32($start, 0)
    $end = [bitconverter]::GetBytes($end)
    [array]::Reverse($end)
    $end = [bitconverter]::ToUInt32($end, 0)
}

# Iterate over all addresses
for( $addr = $start+1; $addr -lt $end; $addr++){

    # Convert for endianness if needed
    if( [bitconverter]::IsLittleEndian ){
        $tmp = [bitconverter]::GetBytes($addr)
        [array]::Reverse($tmp)
        $address = [IPAddress]([bitconverter]::ToUInt32($tmp,0))
    } else {
        $address = [IPAddress]$addr
    }

    # Initialize Host Results
    $host_report = @{
        "host" = $address.IPAddressToString;
        "ports" = @();
    }

    Write-Progress -Activity "[scanning]" -Status "$($address.IPAddressToString): attempting ping scan" -PercentComplete ((($addr-$start)/($end-$start))*100)

    # Ignore this IP if we can't ping it
    if( -not (Test-Connection -BufferSize 4 -Count 1 -Quiet -ComputerName $address.IPAddressToString) ){ continue }

    # The host is up
    $host_report["up"] = $true

    Write-Progress -Activity "[scanning]" -Status "$($address.IPAddressToString): host is up" -PercentComplete ((($addr-$start)/($end-$start))*100)

    # Test each TCP port
    foreach ( $port in $tcp ) {
        try {
            $socket = new-object System.Net.Sockets.TcpClient($address.IPAddressToString, $port)
            if( $socket.Connected ){
                $host_report["ports"] += New-Object -TypeName psobject -Property @{
                    "type" = "tcp";
                    "port" = $port;
                    "state" = "open";
                }
                $socket.Close()
            }
        } Catch {}
    }

    # Setup data to send on UDP
    $packet = [Text.Encoding]::ASCII.GetBytes($data)

    # Test each UDP port
    foreach ( $port in $udp ){
        # Open a connection, setup the timeout and send our data
        $socket = new-object System.Net.Sockets.UdpClient($address.IPAddressToString, $port)
        $socket.client.ReceiveTimeout = $timeout
        [void]$socket.Send($packet, $packet.length)

        # Setup an endpoint to receive responses
        $recv = new-object System.Net.IPEndPoint([System.Net.IPAddress]::Any, 0)

        try {
            # Attempt to receive the data within the timeout
            $received = $socket.Receive([ref]$recv)
            [string]$receivedData = [Text.Encoding]::ASCII.GetString($received)
            # If we received data, the port is open
            if ( $receivedData ) {
                $host_report["ports"] += New-Object -TypeName psobject -Property @{
                    "type" = "udp";
                    "port" = $port;
                    "state" = "open";
                }
            }
        } Catch {
            # The response was not rejected, it timed out. The port _may_ be open
            # If there was an exception, and it didn't time out, then it was likely
            # rejected with an ICMP packet. This means the port is closed.
            if ( $Error[0].ToString() -match "\bRespond after a period of time\b" ) {
                $host_report["ports"] += New-Object -TypeName psobject -Property @{
                    "type" = "udp";
                    "port" = $port;
                    "state" = "open|filtered";
                }
            }
        }

        # Close the socket
        $socket.Close()

        # Packets lost due to collision
        Start-Sleep -Milliseconds $interval
    }

    # Add the host to the report
    $report += $(New-Object -TypeName psobject -Property $host_report)
}

return $report
