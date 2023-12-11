import "pe"

rule MAL_BurningUmbrella_Sample_18
{
	meta:
		description = "Detects malware sample from Burning Umbrella report"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://401trg.pw/burning-umbrella/"
		date = "2018-05-04"
		hash1 = "d8df60524deb6df4f9ddd802037a248f9fbdd532151bb00e647b233e845b1617"
		hash2 = "c55cb6b42cfabf0edf1499d383817164d1b034895e597068e019c19d787ea313"
		hash3 = "32144ba8370826e069e5f1b6745a3625d10f50a809f3f2a72c4c7644ed0cab03"
		hash4 = "ae616003d85a12393783eaff9778aba20189e423c11c852e96c29efa6ecfce81"
		hash5 = "95b6e427883f402db73234b84a84015ad7f3456801cb9bb19df4b11739ea646d"
		hash6 = "1419ba36aae1daecc7a81a2dfb96631537365a5b34247533d59a70c1c9f58da2"
		hash7 = "6a5a9b0ae10ce6a0d5e1f7d21d8ea87894d62d0cda00db005d8d0de17cae7743"
		hash8 = "74e348068f8851fec1b3de54550fe09d07fb85b7481ca6b61404823b473885bb"
		hash9 = "adb9c2fe930fae579ce87059b4b9e15c22b6498c42df01db9760f75d983b93b2"
		hash0 = "23f28b5c4e94d0ad86341c0b9054f197c63389133fcd81dd5e0cf59f774ce54b"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "c:\\tmp\\tran.exe" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <200KB and (pe.imphash()=="11675b4db0e7df7b29b1c1ef6f88e2e1" or pe.imphash()=="364e1f68e2d412db34715709c68ba467" or pe.exports("deKernel") or 1 of them )
}
