param (
    [Parameter(Mandatory=$true)][IPAddress]$ip,
    [Parameter(Mandatory=$true)][IPAddress]$mask,
    [int[]]$tcp = @(),
    [int[]]$udp = @(),
    [int]$timeout = 1000,
    [int]$interval = 1000
)

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
for( $addr = $start; $addr -lt $end; $addr++){

    # Convert for endianness if needed
    if( [bitconverter]::IsLittleEndian ){
        $tmp = [bitconverter]::GetBytes($addr)
        [array]::Reverse($tmp)
        $address = [IPAddress]([bitconverter]::ToUInt32($tmp,0))
    } else {
        $address = [IPAddress]$addr
    }

    Write-Progress -Activity "[scanning]" -Status "$($address.IPAddressToString): attempting ping scan" -PercentComplete ((($addr-$start)/($end-$start))*100)

    # Ignore this IP if we can't ping it
    if( -not (Test-Connection -BufferSize 4 -Count 1 -Quiet -ComputerName $address.IPAddressToString) ){ continue }

    Write-Progress -Activity "[scanning]" -Status "$($address.IPAddressToString): host is up" -PercentComplete ((($addr-$start)/($end-$start))*100)

    # Test each TCP port
    foreach ( $port in $tcp ) {
        try {
            $socket = new-object System.Net.Sockets.TcpClient($address.IPAddressToString, $port)
            if( $socket.Connected ){
                Write-Host "`r[$($address.IPAddressToString)] tcp/$port is open"
                $socket.Close()
            }
        } Catch {}
    }

    # Setup data to send on UDP
    $data = [Text.Encoding]::ASCII.GetBytes("$(Get-Date)")

    # Test each UDP port
    foreach ( $port in $udp ){
        # Open a connection, setup the timeout and send our data
        $socket = new-object System.Net.Sockets.UdpClient($address.IPAddressToString, $port)
        $socket.client.ReceiveTimeout = $timeout
        [void]$socket.Send($data, $data.length)

        # Setup an endpoint to receive responses
        $recv = new-object System.Net.IPEndPoint([System.Net.IPAddress]::Any, 0)

        try {
            # Attempt to receive the data within the timeout
            $received = $socket.Receive([ref]$recv)
            [string]$receivedData = [Text.Encoding]::ASCII.GetString($received)
            # If we received data, the port is open
            if ( $receivedData ) {
                Write-Host "[$($address.IPAddressToString)] udp/$port is open"
            }
        } Catch {
            # The response was not rejected, it timed out. The port _may_ be open
            # If there was an exception, and it didn't time out, then it was likely
            # rejected with an ICMP packet. This means the port is closed.
            if ( $Error[0].ToString() -match "\bRespond after a period of time\b" ) {
                Write-Host "[$($address.IPAddressToString)] udp/$port is open|filtered"
            }
        }

        # Close the socket
        $socket.Close()

        # Packets lost due to collision
        Start-Sleep -Milliseconds $interval
    }
}
