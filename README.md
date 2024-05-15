# fTest-Port
This Function will Test TCP Ports on Remote Computers for Status Open or Closed.
Please Note, that when a Port seems to be Closed, it is also possible that there is no active Listener on Target Server. 
A closed Port does not mean, that a Firewall will Block a Connection. Maybe there is just No Listener on Target Server.

Please note, that the Script can only be executed Remotly, when Port 80 and 5985 to the Target Server is Open. 
Otherwise, the Script cannot Execute the Command `'Invoke-Command`'. For a simple Port Test from Localhost against a single 
Target Server with a maximum of 5 Target Ports at the same time, the Function will use the 'Test-NetConnection' Methode.
The Test-NetConnection Methode is more precise but takes a long time if a Port is closed. 
For all other Cases - Testing from Remote Source Servers or more than one Target Servers or testing more than 5 Ports at 
the same Time, the Function will use the '.NET TCP Client' Methode. This Metode is much faster, but rarely we will see a 
wrong Result. ;-(
