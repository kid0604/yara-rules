rule InjectionParameters
{
	meta:
		description = "Chinese Hacktool Set - file InjectionParameters.vb"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "4f11aa5b3660c45e527606ee33de001f4994e1ea"
		os = "windows"
		filetype = "script"

	strings:
		$s0 = "Public Shared ReadOnly Empty As New InjectionParameters(-1, \"\")" fullword ascii
		$s1 = "Public Class InjectionParameters" fullword ascii

	condition:
		filesize <13KB and all of them
}
