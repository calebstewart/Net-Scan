param (
    [Parameter(Mandatory=$true)][IPAddress]$ip,
    [Parameter(Mandatory=$true)][IPAddress]$mask,
    [Parameter(Mandatory=$true)][int[]]$ports
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

    # Test each port
    foreach ( $port in $ports ) {
        try {
            $socket = new-object System.Net.Sockets.TcpClient($address.IPAddressToString, $port)
            if( $socket.Connected ){
                Write-Host "`r[$($address.IPAddressToString)] port $port is open"
                $socket.Close()
            }
        } Catch {}
    }
}
