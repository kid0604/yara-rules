rule Windows_Trojan_CobaltStrike_ee756db7
{
	meta:
		author = "Elastic Security"
		id = "ee756db7-e177-41f0-af99-c44646d334f7"
		fingerprint = "e589cc259644bc75d6c4db02a624c978e855201cf851c0d87f0d54685ce68f71"
		creation_date = "2021-03-23"
		last_modified = "2021-08-23"
		description = "Attempts to detect Cobalt Strike based on strings found in BEACON"
		threat_name = "Windows.Trojan.CobaltStrike"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		filetype = "executable"

	strings:
		$a1 = "%s.4%08x%08x%08x%08x%08x.%08x%08x%08x%08x%08x%08x%08x.%08x%08x%08x%08x%08x%08x%08x.%08x%08x%08x%08x%08x%08x%08x.%x%x.%s" ascii fullword
		$a2 = "%s.3%08x%08x%08x%08x%08x%08x%08x.%08x%08x%08x%08x%08x%08x%08x.%08x%08x%08x%08x%08x%08x%08x.%x%x.%s" ascii fullword
		$a3 = "ppid %d is in a different desktop session (spawned jobs may fail). Use 'ppid' to reset." ascii fullword
		$a4 = "IEX (New-Object Net.Webclient).DownloadString('http://127.0.0.1:%u/'); %s" ascii fullword
		$a5 = "IEX (New-Object Net.Webclient).DownloadString('http://127.0.0.1:%u/')" ascii fullword
		$a6 = "%s.2%08x%08x%08x%08x%08x%08x%08x.%08x%08x%08x%08x%08x%08x%08x.%x%x.%s" ascii fullword
		$a7 = "could not run command (w/ token) because of its length of %d bytes!" ascii fullword
		$a8 = "%s.2%08x%08x%08x%08x%08x%08x.%08x%08x%08x%08x%08x%08x.%x%x.%s" ascii fullword
		$a9 = "%s.2%08x%08x%08x%08x%08x.%08x%08x%08x%08x%08x.%x%x.%s" ascii fullword
		$a10 = "powershell -nop -exec bypass -EncodedCommand \"%s\"" ascii fullword
		$a11 = "Could not open service control manager on %s: %d" ascii fullword
		$a12 = "%d is an x64 process (can't inject x86 content)" ascii fullword
		$a13 = "%d is an x86 process (can't inject x64 content)" ascii fullword
		$a14 = "Failed to impersonate logged on user %d (%u)" ascii fullword
		$a15 = "could not create remote thread in %d: %d" ascii fullword
		$a16 = "%s.1%08x%08x%08x%08x%08x%08x%08x.%x%x.%s" ascii fullword
		$a17 = "could not write to process memory: %d" ascii fullword
		$a18 = "Could not create service %s on %s: %d" ascii fullword
		$a19 = "Could not delete service %s on %s: %d" ascii fullword
		$a20 = "Could not open process token: %d (%u)" ascii fullword
		$a21 = "%s.1%08x%08x%08x%08x%08x%08x.%x%x.%s" ascii fullword
		$a22 = "Could not start service %s on %s: %d" ascii fullword
		$a23 = "Could not query service %s on %s: %d" ascii fullword
		$a24 = "Could not connect to pipe (%s): %d" ascii fullword
		$a25 = "%s.1%08x%08x%08x%08x%08x.%x%x.%s" ascii fullword
		$a26 = "could not spawn %s (token): %d" ascii fullword
		$a27 = "could not open process %d: %d" ascii fullword
		$a28 = "could not run %s as %s\\%s: %d" ascii fullword
		$a29 = "%s.1%08x%08x%08x%08x.%x%x.%s" ascii fullword
		$a30 = "kerberos ticket use failed:" ascii fullword
		$a31 = "Started service %s on %s" ascii fullword
		$a32 = "%s.1%08x%08x%08x.%x%x.%s" ascii fullword
		$a33 = "I'm already in SMB mode" ascii fullword
		$a34 = "could not spawn %s: %d" ascii fullword
		$a35 = "could not open %s: %d" ascii fullword
		$a36 = "%s.1%08x%08x.%x%x.%s" ascii fullword
		$a37 = "Could not open '%s'" ascii fullword
		$a38 = "%s.1%08x.%x%x.%s" ascii fullword
		$a39 = "%s as %s\\%s: %d" ascii fullword
		$a40 = "%s.1%x.%x%x.%s" ascii fullword
		$a41 = "beacon.x64.dll" ascii fullword
		$a42 = "%s on %s: %d" ascii fullword
		$a43 = "www6.%x%x.%s" ascii fullword
		$a44 = "cdn.%x%x.%s" ascii fullword
		$a45 = "api.%x%x.%s" ascii fullword
		$a46 = "%s (admin)" ascii fullword
		$a47 = "beacon.dll" ascii fullword
		$a48 = "%s%s: %s" ascii fullword
		$a49 = "@%d.%s" ascii fullword
		$a50 = "%02d/%02d/%02d %02d:%02d:%02d" ascii fullword
		$a51 = "Content-Length: %d" ascii fullword

	condition:
		6 of ($a*)
}
