
Function fTest-Port {
	<#
		.NOTES
			Author: Buchser Roger
			
		.SYNOPSIS
			This Function will Test TCP Ports on Remote Computers for Status Open or Closed.
			Please Note, that when a Port seems to be Closed, it is also possible that there is no active Listener on Target Server. 
			A closed Port does not mean, that a Firewall will Block a Connection. Maybe there is just No Listener on Target Server.
			
		.DESCRIPTION
			Please note, that the Script can only be executed Remotly, when Port 80 and 5985 to the Target Server is Open. 
			Otherwise, the Script cannot Execute the Command `'Invoke-Command`'. For a simple Port Test from Localhost against a single 
			Target Server with a maximum of 5 Target Ports at the same time, the Function will use the 'Test-NetConnection' Methode.
			The Test-NetConnection Methode is more precise but takes a long time if a Port is closed. 
			For all other Cases - Testing from Remote Source Servers or more than one Target Servers or testing more than 5 Ports at 
			the same Time, the Function will use the '.NET TCP Client' Methode. This Metode is much faster, but rarely we will see a 
			wrong Result. ;-(
			
		.PARAMETER SourceServers
			Define the Source Servers from which Server the Test will be executed. You can define multiple Source Servers delimited by `',`'. 
			If the Parameter Source Server is not set, the Test will be executed from Localhost
		
		.PARAMETER TargetServers
			Define the Target Servers from which Server the Test will be executed. You can define multiple Target Servers delimited by `',`'.
		
		.PARAMETER TargetPorts
			Define the Ports that should be Test on Target Servers. You can define multiple Ports delimited by `',`'. 
			Testing a Range of Ports use @(5060..5066) as an Example for Testing all Ports from 5060 to 5066. 
			If you do not specify any Target Ports, the most used importand Ports 80,135,443,445 and 5985 for Powershell will be used.
		
		.PARAMETER AllPorts
			Checks a Server for all Ports (1..65535) 
		
		.PARAMETER ExportResultAsCsv
			At the End of the Checks, the Result will be Displayed as Table on Console and also will be exported 
			as CSV under '$Date - Check Ports.csv`.
		
		.PARAMETER Timeout
			Define the Timeout in Miliseconds to wait after TCP Client try to Connect to Target Server until the the Script will 
			check from Status `'Connected`'. Default is 10 ms.
		
		.EXAMPLE
			fTest-Port LAB-SRV-01,LAB-SRV-02,LAB-SRV-03,LAB-SRV-04
			Test Well Known Ports 80,135,443,445 and 5985 from Localhost to all SRV Servers.
		
		.EXAMPLE
			fTest-Port -SourceServers LAB-MGT-01,LAB-MGT-02 -TargetServers (1..8 | ForEach {"LAB-EX-0$_"}) -TargetPorts @(1..1024) -ExportResultAsCsv
			Test all low Ports (Port 1 until Port 1024) from all Management Servers to all 8 Exchange Mailbox Servers.
			Results will be exported as CSV-File.
		
		.EXAMPLE
			fTest-Port -TargetServers LAB-EX-01 -TargetPorts 25
			Test a single TCP Port from Localhost to a remote single TargetServer on Port 25.
		
		.EXAMPLE
			fTest-Port -TargetServers 192.168.76.54 -TargetPorts 443
			Test a single TCP Port from Localhost to a remote single TargetServer by IP Address.
		
		.EXAMPLE
			fTest-Port -TargetServers outlook -TargetPorts 80,443,5985,5986
			Test all TCP Ports from Localhost to a single Remote System 'outlook' on multiple Ports (Remote Powershell).
			
		.EXAMPLE
			fTest-Port LAB-EX-01 -AllPorts
			Test all TCP Ports (1..65535) from Localhost to TargetServer LAB-EX-01. Only available Ports will be displayed on Console.
		
		.EXAMPLE
			fTest-Port -SourceServers LAB-EX-01 -TargetServers LAB-EX-06 -TargetPorts 443,445
			Test a TCP Port from a single remote SourceServer to a single remote TargetServer on Ports 443 and 445 (HTTPS and SMB).
		
		.EXAMPLE
			fTest-Port -SourceServers (1..8 | ForEach {"LAB-EX-0$_"}) -TargetServers LAB-EDG-10,LAB-EDG-11 -TargetPorts 25,50636
			Test a TCP Port multiple remote SourceServer to multiple remote TargetServer on multiple Ports.
		
		.EXAMPLE
			fTest-Port -SourceServers LAB-MGT-01,LAB-MGT-02 -TargetServers mailrelay -TargetPorts 25
			Test all TCP Ports from management Servers to Mailrelay Server on single Port 25 (SMTP).
		
		.EXAMPLE
			fTest-Port -SourceServers (1..8 | ForEach {"LAB-EX-0$_"}) -TargetServers LAB-SFB-01,LAB-SFB-02 -TargetPorts @(5060..5068)
			Test all TCP Ports from all Exchange Mailbox Servers to all SkypeServers with Port Range from Port 5060 to Port 5068.
				
		.LINK
			https://stackoverflow.com/questions/9566052/how-to-check-network-port-access-and-display-useful-message
			https://docs.microsoft.com/en-us/powershell/module(nettcpip/test-netconnection?view=win10-ps
			https://en.wikipedia.org/wiki/List_of_TCP_and_UDP_port_numbers
    #>
	
	[CmdletBinding(DefaultParameterSetName="SingleQuery")]
	PARAM (
		[Parameter(Mandatory=$True,Position=0)][Alias("Servers","DestinationServers")][Array]$TargetServers,
		[Parameter(ParameterSetName="SingleQuery",Mandatory=$False)][Array]$SourceServers = $Env:COMPUTERNAME,
		[Parameter(ParameterSetName="SingleQuery",Mandatory=$False,Position=1)][Alias("Ports")][ValidateRange(1,65535)][Array]$TargetPorts = @("80","135","443","445","5985"),
		[Parameter(ParameterSetName="AllPorts",Mandatory=$False)][Switch]$AllPorts,
		[Parameter(ParameterSetName="AllPorts",Mandatory=$False)][Switch]$WellKnownPorts,
		[Parameter(ParameterSetName="AllPorts",Mandatory=$False)][Switch]$LowPorts,
		[Parameter(ParameterSetName="AllPorts",Mandatory=$False)][Switch]$HighPorts,
		[Parameter(ParameterSetName="AllPorts",Mandatory=$False)][ValidateRange(1,100)][Int]$Timeout = 10,
		[Parameter(Mandatory=$False)][Switch]$ExportResultAsCsv
	)
	
	$SourceServersHostNames = $Null
	ForEach ($SourceServer in $SourceServers) {
		Try {
			[IpAddress]$SourceServer | Out-Null
			Try {
				[Array]$SourceServersHostNames += ((Resolve-DnsName $SourceServer).NameHost).Split('.')[0]
			} Catch {
				Write-Warning "Cannot find Hostname in DNS for IP `'$SourceServer´'. You cannot use the Function fTest-Port for this SourceServer..."
				Sleep 5
			}
		} Catch {
			[Array]$SourceServersHostNames += ((Resolve-DnsName $SourceServer).Name).Split('.')[0]
		}
	}
	
	$SessionOptions = New-PSSessionOption -NoMachineProfile -OpenTimeout 30000 -OperationTimeout 30000 -SkipRevocationCheck
	$SourceServersHostNames | New-PsSession -EnableNetworkAccess -SessionOption $SessionOptions | Out-Null
	$SourceServersHostNames = $Null
	
	Function ffTestPort {
		[CmdletBinding()]
		Param (
			[Array]$SourceHosts,
			[Array]$TargetHosts,
			[Array]$TargetPorts
		)
		
		$ServersNotFound = @()
		[Array]$AllHosts = $SourceHosts + $TargetHosts | Sort -Unique
		
		[Array]$HostIpTable = @()

		ForEach ($Entry in $AllHosts) {
			Try {
				$IP = ([System.Net.Dns]::GetHostAddresses($Entry) | Where {$_.AddressFamily -eq 'InterNetwork'}).IPAddressToString
				Try {
					[IpAddress]$IpCheck = $Entry
					[String]$Hostname = $IpCheck.IPAddressToString
				} Catch {
					[String]$Hostname = $Entry.Split(".")[0].ToUpper()
				}
			} Catch {
				$IP = "x.x.x.x"
				[String]$Hostname = $Entry
				$ServersNotFound += $Entry
			}
			$Obj = New-Object PsObject
			$Obj | Add-Member NoteProperty -Name ServerFQDN -Value $Entry
			$Obj | Add-Member NoteProperty -Name ServerName -Value $Hostname
			$Obj | Add-Member NoteProperty -Name ServerIP -Value $IP
			$HostIpTable += $Obj
		}
		
		$NewPortMatrix = @()
		ForEach ($SourceHost in $SourceHosts) {
			$SourceServer = $SourceServerFQDN = $SourceServerIp = $Null
			$SourceServer = ($HostIpTable | Where {$_.ServerFQDN -eq $SourceHost}).ServerName
			$SourceServerFQDN = ($HostIpTable | Where {$_.ServerFQDN -eq $SourceHost}).ServerFQDN
			$SourceServerIp = ($HostIpTable | Where {$_.ServerFQDN -eq $SourceHost}).ServerIP
			$NrOfSourceHosts++
			Write-Verbose "Create Port Matrix for $SourceServer `($NrOfSourceHosts/$($SourceHosts.Count)`)"
			ForEach ($TargetHost in $TargetHosts) {
				$TargetServer = $TargetServerFQDN = $TargetServerIp = $Null
				$TargetServer = ($HostIpTable | Where {$_.ServerFQDN -eq $TargetHost}).ServerName
				$TargetServerFQDN = ($HostIpTable | Where {$_.ServerFQDN -eq $TargetHost}).ServerFQDN
				$TargetServerIp = ($HostIpTable | Where {$_.ServerFQDN -eq $TargetHost}).ServerIP
				ForEach ($TargetPort in $TargetPorts) {
					$Obj = New-Object PsObject
					$Obj | Add-Member NoteProperty -Name SourceServer -Value $SourceServer
					$Obj | Add-Member NoteProperty -Name SourceServerFQDN -Value $SourceServerFQDN
					$Obj | Add-Member NoteProperty -Name SourceServerIp -Value $SourceServerIp
					$Obj | Add-Member NoteProperty -Name TargetServer -Value $TargetServer
					$Obj | Add-Member NoteProperty -Name TargetServerFQDN -Value $TargetServerFQDN
					$Obj | Add-Member NoteProperty -Name TargetServerIp -Value $TargetServerIp
					$Obj | Add-Member NoteProperty -Name TargetPort -Value $TargetPort
					$Obj | Add-Member NoteProperty -Name Result -Value "N/A"
					$NewPortMatrix += $Obj
				}
			}
		}
		
		If ($ServersNotFound) {
			Write-Host "WARNING: Cannot find all Servers in DNS. Ignoring this Server..." -f Yellow
			Write-Host $ServersNotFind | Select -Unique
		}
		
		$CheckPortScriptBlock = {
			Param (
				[String]$SourceServer = $Args[0],
				[Array]$PortMatrix = $Args[1],
				[Array]$HostTable = $Args[2]
			)
			ForEach ($Line in ($PortMatrix | Where {$_.SourceServer -eq $SourceServer})) {
				$TargetServer = $Line.TargetServerFQDN
				ForEach ($TargetPort in $Line.TargetPort) {
					$RequestCallback = $State = $Null
					$Client = New-Object System.Net.Sockets.TcpClient
					$BeginConnect = $Client.BeginConnect($TargetServer,$TargetPort,$RequestCallback,$State)
					Start-Sleep -milli 50
					If ($Client.Connected) {
						Write-Host "$($Env:COMPUTERNAME) " -f Green -NoNewLine
						Write-Host "[$($Line.SourceServerIp)]".PadRight(16,' ') -NoNewLine
						Write-Host " > " -f DarkGray -NoNewLine
						Write-Host "$($Line.TargetServer) " -f Green -NoNewLine
						Write-Host "[$($Line.TargetServerIp)]".PadRight(16,' ') -NoNewLine
						Write-Host " > " -f DarkGray -NoNewLine
						Write-Host "Port: $TargetPort".PadRight(11,' ') -f Green -NoNewLine
						Write-Host " > " -f DarkGray -NoNewLine
						Write-Host "Successfully" -f Green
						$Line.Result = "Successfull"
					} Else {
						Write-Host "$($Env:COMPUTERNAME) " -f Red -NoNewLine
						Write-Host "[$($Line.SourceServerIp)]".PadRight(16,' ') -NoNewLine
						Write-Host " > " -f DarkGray -NoNewLine
						Write-Host "$($Line.TargetServer) " -f Red -NoNewLine
						Write-Host "[$($Line.TargetServerIp)]".PadRight(16,' ') -NoNewLine
						Write-Host " > " -f DarkGray -NoNewLine
						Write-Host "Port: $TargetPort".PadRight(11,' ') -f Red -NoNewLine
						Write-Host " > " -f DarkGray -NoNewLine
						Write-Host "Failed" -f Red
						$Line.Result = "Failed"
					}
					$Client.Close()
				}
			}
			Return $PortMatrix
		}
			
		$UpdatedPortMatrix = $NewPortMatrix
		ForEach ($SourceServer in ($NewPortMatrix.SourceServer | Select -Unique)) {
			If ($Env:COMPUTERNAME -eq $SourceServer) {
				Write-Verbose "Working on $($SourceServer.ToUpper()) [Local Host]"
				$UpdatedPortMatrix = & $CheckPortScriptBlock -SourceServer $SourceServer -PortMatrix $UpdatedPortMatrix -HostTable $HostIpTable
			} Else {
				Write-Verbose "Working on $($SourceServer.ToUpper()) [Remote Host]"
				Try {
					$UpdatedPortMatrix = Invoke-Command -ComputerName $SourceServer -Argumentlist $SourceServer,$UpdatedPortMatrix,$HostIpTable -ScriptBlock $CheckPortScriptBlock -ErrorAction Stop
				} Catch {
					Write-Host "`nCannot connect to Remote Server `'$SourceServer`'. WinRM Port 5985 is may be closed. Cannot execute Invoke-Command on Remote Server." -f Yellow
					<#
					$Continue = Read-Host "Do you want to Continue Testing Ports? Source Server `'$SourceServer`' will be ignored... (Y/N)"
					If ($Continue -notmatch "[yYjJ]") {Break}
					#>
				}
			}
		}
		Return $UpdatedPortMatrix
	}
	
	Write-Host
	Switch ($PsCmdlet.ParameterSetName) {
		"SingleQuery" {
			# Use Test-NetConnection Methode when testing from Localhost against maximum 1 Target Server and maximum 5 Ports. (Test-NetConnection Methode uses more Time...)
			If (($SourceServersHostNames -eq $Env:COMPUTERNAME) -AND (($TargetServers | Measure).Count -eq 1) -AND (($TargetPorts | Measure).Count -le 5)) {
				$FinalResult = @()
				ForEach ($TargetServer in $TargetServers) {
					ForEach ($TargetPort in $TargetPorts) {
						$Obj = New-Object PsObject
						$Result = Test-NetConnection -ComputerName $TargetServer -Port $TargetPort -WarningAction SilentlyContinue
						$Obj | Add-Member NoteProperty -Name SourceServer -Value $Env:COMPUTERNAME
						$Obj | Add-Member NoteProperty -Name SourceServerIp -Value $Result.SourceAddress.IPAddress
						Try {
							[IpAddress]$Result.ComputerName | Out-Null
							$Obj | Add-Member NoteProperty -Name TargetServer -Value (Resolve-DnsName $Result.ComputerName).NameHost.ToLower()
						} Catch {
							$Obj | Add-Member NoteProperty -Name TargetServer -Value $Result.ComputerName.ToUpper()
						}
						$Obj | Add-Member NoteProperty -Name TargetServerIp -Value $Result.RemoteAddress.IPAddressToString
						$Obj | Add-Member NoteProperty -Name TargetPort -Value $Result.RemotePort
						If ($Result.TcpTestSucceeded -eq $True) {
							Write-Host "$($Env:COMPUTERNAME) " -f Green -NoNewLine
							Write-Host "[$($Obj.SourceServerIp)]".PadRight(16,' ') -NoNewLine
							Write-Host " > " -f DarkGray -NoNewLine
							Write-Host "$($Obj.TargetServer) " -f Green -NoNewLine
							Write-Host "[$($Obj.TargetServerIp)]".PadRight(16,' ') -NoNewLine
							Write-Host " > " -f DarkGray -NoNewLine
							Write-Host "Port: $($Obj.TargetPort)".PadRight(11,' ') -f Green -NoNewLine
							Write-Host " > " -f DarkGray -NoNewLine
							Write-Host "Successfully" -f Green
							$Obj | Add-Member NoteProperty -Name Result -Value Successfully
						} Else {
							Write-Host "$($Env:COMPUTERNAME) " -f Red -NoNewLine
							Write-Host "[$($Obj.SourceServerIp)]".PadRight(16,' ') -NoNewLine
							Write-Host " > " -f DarkGray -NoNewLine
							Write-Host "$($Obj.TargetServer) " -f Red -NoNewLine
							Write-Host "[$($Obj.TargetServerIp)]".PadRight(16,' ') -NoNewLine
							Write-Host " > " -f DarkGray -NoNewLine
							Write-Host "Port: $($Obj.TargetPort)".PadRight(11,' ') -f Red -NoNewLine
							Write-Host " > " -f DarkGray -NoNewLine
							Write-Host "Failed" -f Red
							$Obj | Add-Member NoteProperty -Name Result -Value Failed
						}
					}
					$FinalResult += $Obj
				}
				fWrite-Info -cr "Checking Ports using 'Test-NetConnection' Methode`n" -f Cyan
			} ElseIf (($SourceServersHostNames -ne $Env:COMPUTERNAME) -AND (($TargetServers | Measure).Count -eq 1) -AND (($TargetPorts | Measure).Count -le 5)) {
				$FinalResult = @()
				ForEach ($SourceServer in $SourceServersHostNames) {
					ForEach ($TargetServer in $TargetServers) {
						ForEach ($TargetPort in $TargetPorts) {
							$Result = Invoke-Command -Session ($PsSessions | Where {$SourceServer -match $_.ComputerName}) -ScriptBlock {Test-NetConnection $Using:TargetServer -Port $Using:TargetPort -WarningAction SilentlyContinue}
							$Obj = New-Object PsObject
							$Obj | Add-Member NoteProperty -Name SourceServer -Value $SourceServer
							$Obj | Add-Member NoteProperty -Name SourceServerIp -Value (Resolve-DnsName $SourceServer).IPAddress
							Try {
								[IpAddress]$Result.ComputerName | Out-Null
								$Obj | Add-Member NoteProperty -Name TargetServer -Value (Resolve-DnsName $Result.ComputerName).NameHost.ToLower()
							} Catch {
								$Obj | Add-Member NoteProperty -Name TargetServer -Value $Result.ComputerName.ToUpper()
							}
							$Obj | Add-Member NoteProperty -Name TargetServerIp -Value $Result.RemoteAddress.IPAddressToString
							$Obj | Add-Member NoteProperty -Name TargetPort -Value $Result.RemotePort
							If ($Result.TcpTestSucceeded -eq $True) {
								Write-Host "$($Obj.SourceServer) " -f Green -NoNewLine
								Write-Host "[$($Obj.SourceServerIp)]".PadRight(16,' ') -NoNewLine
								Write-Host " > " -f DarkGray -NoNewLine
								Write-Host "$($Obj.TargetServer) " -f Green -NoNewLine
								Write-Host "[$($Obj.TargetServerIp)]".PadRight(16,' ') -NoNewLine
								Write-Host " > " -f DarkGray -NoNewLine
								Write-Host "Port: $($Obj.TargetPort)".PadRight(11,' ') -f Green -NoNewLine
								Write-Host " > " -f DarkGray -NoNewLine
								Write-Host "Successfully" -f Green
								$Obj | Add-Member NoteProperty -Name Result -Value Successfully
							} Else {
								Write-Host "$($Obj.SourceServer) " -f Red -NoNewLine
								Write-Host "[$($Obj.TargetServerIp)]".PadRight(16,' ') -NoNewLine
								Write-Host " > " -f DarkGray -NoNewLine
								Write-Host "$($Obj.TargetServer) " -f Red -NoNewLine
								Write-Host "[$($Obj.TargetServerIp)]".PadRight(16,' ') -NoNewLine
								Write-Host " > " -f DarkGray -NoNewLine
								Write-Host "Port: $($Obj.TargetPort)".PadRight(11,' ') -f Red -NoNewLine
								Write-Host " > " -f DarkGray -NoNewLine
								Write-Host "Failed" -f Red
								$Obj | Add-Member NoteProperty -Name Result -Value Failed
							}
						}
						$FinalResult += $Obj
					}
				}
				fWrite-Info -cr "Checking Ports using 'Test-NetConnection' Methode`n" -f Cyan
			} Else {
				$SourceHosts = $SourceServersHostNames | ForEach {
					If ($_ -notmatch $RegexIPv4Pattern) {
						Try {
							([System.Net.Dns]::GetHostEntry($_)).HostName
						} Catch {}
					} Else {
						$_
					}
				}
							
				$TargetHosts = $TargetServers | ForEach {
					If ($_ -notmatch $RegexIPv4Pattern) {
						Try {
							([System.Net.Dns]::GetHostEntry($_)).HostName
						} Catch {}
					} Else {
						$_
					}
				}
				
				If ($Verbose) {
					$FinalResult = ffTestPort -SourceHosts $SourceHosts -TargetHosts $TargetHosts -TargetPorts $TargetPorts -Verbose
				} Else {
					$FinalResult = ffTestPort -SourceHosts $SourceHosts -TargetHosts $TargetHosts -TargetPorts $TargetPorts
				}
				fWrite-Info -cr "Checking Ports using '.NET TCP Client' Methode`n" -f Cyan
			}
		}
		"AllPorts" {
			cls
			Write-Host "`n`n`n`n`n"
			fWrite-Info -crcr "Checking all Ports... Only available Ports will be displayed... Please wait..."
			$FinalResult = @()
			$LocalHostIp = (Get-NetIPConfiguration).IPv4Address.IPAddress
			If ($AllPorts) {$PortRange = @(0..65535)}
			ElseIf ($WellKnownPorts) {$PortRange = @(0..1023)}
			ElseIf ($LowPorts) {$PortRange = @(0..9999)}
			ElseIf ($HighPorts) {$PortRange = @(49152..65535)}
			Else {$PortRange = @(0..65535)}
			[Int]$NrOfPortsToCheck = $PortRange[-1]-$PortRange[0]
			
			cls
			Write-Host "`n`n`n`n`n`n`n`n"
			ForEach ($TargetServer in $TargetServers) {
				$TargetServerIp = (Resolve-DnsName $TargetServer).IpAddress
				$i=0
				ForEach ($TargetPort in $PortRange) {
					Write-Progress -Activity "Checking Port-Range from $($PortRange[0]) to $($PortRange[-1]) on Server $($TargetServer.ToUpper()). Please wait..." -CurrentOperation "Checking Port $TargetPort" -Status "Processing $i of $NrOfPortsToCheck Ports";$i++
					$RequestCallback = $State = $Null
					$Client = New-Object System.Net.Sockets.TcpClient
					$BeginConnect = $Client.BeginConnect($TargetServer,$TargetPort,$RequestCallback,$State)
					Start-Sleep -milli $Timeout
					If ($Client.Connected) {
						Write-Host "$($Env:COMPUTERNAME) " -f Green -NoNewLine
						Write-Host "[$LocalHostIp]".PadRight(16,' ') -NoNewLine
						Write-Host " > " -f DarkGray -NoNewLine
						Write-Host "$($TargetServer.ToUpper()) " -f Green -NoNewLine
						Write-Host "[$TargetServerIp]".PadRight(16,' ') -NoNewLine
						Write-Host " > " -f DarkGray -NoNewLine
						Write-Host "Port: $TargetPort".PadRight(11,' ') -f Green -NoNewLine
						Write-Host " > " -f DarkGray -NoNewLine
						Write-Host "Successfully" -f Green
						$Obj = New-Object PsObject
						$Obj | Add-Member NoteProperty -Name SourceServer -Value $Env:COMPUTERNAME
						$Obj | Add-Member NoteProperty -Name SourceServerIp -Value $LocalHostIp
						$Obj | Add-Member NoteProperty -Name TargetServer -Value $TargetServer.ToUpper()
						$Obj | Add-Member NoteProperty -Name TargetServerIp -Value $TargetServerIp
						$Obj | Add-Member NoteProperty -Name TargetPort -Value $TargetPort
						$Obj | Add-Member NoteProperty -Name Result -Value Successfully
						$FinalResult += $Obj
					} 
					$Client.Close()
				}
				Write-Progress -Activity "Checking Port-Range from $($PortRange[0]) to $($PortRange[-1]) on Server $($TargetServer.ToUpper()). Please wait..." -Completed
			}
			fWrite-Info -cr "Checking Ports using '.NET TCP Client' Methode`n" -f Cyan
		}
	}

	If ($ExportResultAsCsv) {
		[String]$ResultCsvFile = "$((Get-Date).ToString('yyyy-MM-dd-HHmmss')) - Check Ports.csv"
		$FinalResult | Select SourceServerFQDN,SourceServerIp,TargetServerFQDN,TargetServerIp,TargetPort,Result | Export-Csv -Path $ResultCsvFile -Delimiter ";" -NoTypeInformation -Encoding UTF8
		Write-Host "`n -> See detailed Report under `'$ResultCsvFile`'`n" -f DarkCyan
		Start-Process -FilePath C:\Windows\explorer.exe -ArgumentList "/select, ""$ResultCsvFile"""
	}
	Write-Host
}
