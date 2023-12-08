import "pe"

rule HTMLVariant : FakeM Family HTML Variant
{
	meta:
		description = "Identifier for html variant of FAKEM"
		author = "Katie Kleemola"
		last_updated = "2014-05-20"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = { 8B 55 08 B9 00 50 00 00 8D 3D ?? ?? ?? 00 8B F7 AD 33 C2 AB 83 E9 04 85 C9 75 F5 }
		$s2 = { C6 45 F? (3?|4?) }

	condition:
		$s1 and #s2==16
}
