rule malware_cobaltstrike_workersdevloader
{
	meta:
		description = "CobaltStrike loader using workers.dev"
		author = "JPCERT/CC Incident Response Group"
		hash = "a7e5080067751ef41254ec4c9f3b6e3ac7cdeca703bdddfc9afb194afee3c124"
		hash = "fc7eba3306463b091066b51dc7a890233710b2755b9526f5c1a8365c478caa16"
		os = "windows"
		filetype = "executable"

	strings:
		$xorcode = { 41 8A 0C 10 80 F1 ?? 88 0A 48 FF C2 49 83 E9 01 }
		$jnk = { 48 3B 15 ?? ?? ?? 00 48 8D 05 ?? ?? FF FF 48 89 45 10 74 16 48 89 02 }
		$str = "root\\cimv2" ascii
		$folder = "{80C23C0F-1FE2-45D3-ACA0-4936A6875179}" ascii wide
		$pdb = "G:\\viewer\\bin\\viewerlib.pdb" ascii wide
		$opt1 = "--is_ready=" ascii wide
		$opt2 = "--doc_path=" ascii wide
		$opt3 = "--parent_path=" ascii wide
		$opt4 = "--parent_id=" ascii wide
		$opt5 = "--auto=" ascii wide

	condition:
		uint16(0)==0x5A4D and uint32( uint32(0x3c))==0x00004550 and ($pdb or $folder or 3 of ($opt*) or ($str and $xorcode and #jnk>10))
}
