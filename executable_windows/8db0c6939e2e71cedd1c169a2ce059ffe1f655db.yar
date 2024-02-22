rule Windows_Trojan_PikaBot_95db8b5a
{
	meta:
		author = "Elastic Security"
		id = "95db8b5a-f97d-42bd-a114-e35e031784e2"
		fingerprint = "f9463fa18fc5975aeabf076490bd8fe79c62c822126c5320f90870a9b4032f60"
		creation_date = "2024-02-15"
		last_modified = "2024-02-21"
		description = "Related to Pikabot loader"
		threat_name = "Windows.Trojan.PikaBot"
		reference = "https://www.elastic.co/security-labs/pikabot-i-choose-you"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		filetype = "executable"

	strings:
		$syscall_ZwQueryInfoProcess = { 68 9B 8B 16 88 E8 73 FF FF FF }
		$syscall_ZwCreateUserProcess = { 68 B2 CE 2E CF E8 5F FF FF FF }
		$load_sycall = { 8F 05 ?? ?? ?? ?? 83 C0 04 50 8F 05 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 C4 04 A3 ?? ?? ?? ?? 31 C0 64 8B 0D C0 00 00 00 85 C9 }
		$payload_chunking = { 8A 84 35 ?? ?? ?? ?? 8A 95 ?? ?? ?? ?? 88 84 1D ?? ?? ?? ?? 88 94 35 ?? ?? ?? ?? 02 94 1D ?? ?? ?? ?? }
		$loader_rc4_decrypt_chunk = { F7 FF 8A 84 15 ?? ?? ?? ?? 89 D1 8A 94 1D ?? ?? ?? ?? 88 94 0D ?? ?? ?? ?? 8B 55 08 88 84 1D ?? ?? ?? ?? 02 84 0D ?? ?? ?? ?? 0F B6 C0 8A 84 05 ?? ?? ?? ?? 32 04 32 }

	condition:
		2 of them
}
