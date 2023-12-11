import "pe"
import "math"

rule borland_component
{
	meta:
		author = "_pusher_"
		description = "Borland Component"
		date = "2015-08"
		version = "0.1"
		os = "windows"
		filetype = "executable"

	strings:
		$c0 = { E9 ?? ?? ?? FF 8D 40 00 }

	condition:
		$c0 at pe.entry_point
}
