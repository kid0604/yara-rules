import "pe"

rule Agent_BTZ_Aug17
{
	meta:
		description = "Detects Agent.BTZ"
		author = "Florian Roth (Nextron Systems)"
		reference = "http://www.intezer.com/new-variants-of-agent-btz-comrat-found/"
		date = "2017-08-07"
		hash1 = "6ad78f069c3619d0d18eef8281219679f538cfe0c1b6d40b244beb359762cf96"
		hash2 = "49c5c798689d4a54e5b7099b647b0596fb96b996a437bb8241b5dd76e974c24e"
		hash3 = "e88970fa4892150441c1616028982fe63c875f149cd490c3c910a1c091d3ad49"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "stdole2.tlb" fullword ascii
		$s2 = "UnInstallW" fullword ascii

	condition:
		( uint16(0)==0x5a4d and filesize <900KB and all of them and pe.exports("Entry") and pe.exports("InstallW") and pe.exports("UnInstallW"))
}
