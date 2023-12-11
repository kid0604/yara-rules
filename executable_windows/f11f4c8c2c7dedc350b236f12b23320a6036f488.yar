import "pe"

rule Anthem_DeepPanda_htran_exe
{
	meta:
		description = "Anthem Hack Deep Panda - htran-exe"
		author = "Florian Roth"
		date = "2015/02/08"
		hash = "38e21f0b87b3052b536408fdf59185f8b3d210b9"
		os = "windows"
		filetype = "executable"

	strings:
		$s0 = "%s -<listen|tran|slave> <option> [-log logfile]" fullword ascii
		$s1 = "[-] Gethostbyname(%s) error:%s" fullword ascii
		$s2 = "e:\\VS 2008 Project\\htran\\Release\\htran.pdb" fullword ascii
		$s3 = "[SERVER]connection to %s:%d error" fullword ascii
		$s4 = "-tran  <ConnectPort> <TransmitHost> <TransmitPort>" fullword ascii
		$s5 = "[-] ERROR: Must supply logfile name." fullword ascii
		$s6 = "[-] There is a error...Create a new connection." fullword ascii
		$s7 = "[+] Accept a Client on port %d from %s" fullword ascii
		$s8 = "======================== htran V%s =======================" fullword ascii
		$s9 = "[-] Socket Listen error." fullword ascii
		$s10 = "[-] ERROR: open logfile" fullword ascii
		$s11 = "-slave  <ConnectHost> <ConnectPort> <TransmitHost> <TransmitPort>" fullword ascii
		$s12 = "[+] Make a Connection to %s:%d ......" fullword ascii
		$s14 = "Recv %5d bytes from %s:%d" fullword ascii
		$s15 = "[+] OK! I Closed The Two Socket." fullword ascii
		$s16 = "[+] Waiting another Client on port:%d...." fullword ascii
		$s17 = "[+] Accept a Client on port %d from %s ......" fullword ascii
		$s20 = "-listen <ConnectPort> <TransmitPort>" fullword ascii

	condition:
		10 of them
}
