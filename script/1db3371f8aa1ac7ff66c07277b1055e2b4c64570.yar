rule CobaltStrike_Resources_Template_Py_v3_3_to_v4_x
{
	meta:
		description = "Cobalt Strike's resources/template.py signature for versions v3.3 to v4.x"
		hash = "d5cb406bee013f51d876da44378c0a89b7b3b800d018527334ea0c5793ea4006"
		author = "gssincla@google.com"
		reference = "https://cloud.google.com/blog/products/identity-security/making-cobalt-strike-harder-for-threat-actors-to-abuse"
		date = "2022-11-18"
		os = "windows"
		filetype = "script"

	strings:
		$arch = "platform.architecture()"
		$nope = "WindowsPE"
		$alloc = "ctypes.windll.kernel32.VirtualAlloc"
		$movemem = "ctypes.windll.kernel32.RtlMoveMemory"
		$thread = "ctypes.windll.kernel32.CreateThread"
		$wait = "ctypes.windll.kernel32.WaitForSingleObject"

	condition:
		all of them
}
