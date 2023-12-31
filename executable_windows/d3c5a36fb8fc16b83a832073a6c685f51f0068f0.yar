import "pe"

rule turla_png_dropper
{
	meta:
		author = "Ben Humphrey"
		description = "Detects the PNG Dropper used by the Turla group"
		reference = "https://www.nccgroup.trust/uk/about-us/newsroom-and-events/blogs/2018/november/turla-png-dropper-is-back/"
		date = "2018/11/23"
		hash1 = "6ed939f59476fd31dc4d99e96136e928fbd88aec0d9c59846092c0e93a3c0e27"
		os = "windows"
		filetype = "executable"

	strings:
		$api0 = "GdiplusStartup"
		$api1 = "GdipAlloc"
		$api2 = "GdipCreateBitmapFromStreamICM"
		$api3 = "GdipBitmapLockBits"
		$api4 = "GdipGetImageWidth"
		$api5 = "GdipGetImageHeight"
		$api6 = "GdiplusShutdown"
		$code32 = {
            8B 46 3C               // mov     eax, [esi+3Ch]
            B9 0B 01 00 00         // mov     ecx, 10Bh
            66 39 4C 30 18         // cmp     [eax+esi+18h], cx
            8B 44 30 28            // mov     eax, [eax+esi+28h]
            6A 00                  // push    0
            B9 AF BE AD DE         // mov     ecx, 0DEADBEAFh
            51                     // push    ecx
            51                     // push    ecx
            03 C6                  // add     eax, esi
            56                     // push    esi
            FF D0                  // call eax
        }
		$code64 = {
            48 63 43 3C            // movsxd rax, dword ptr [rbx+3Ch]
            B9 0B 01 00 00         // mov ecx, 10Bh
            BA AF BE AD DE         // mov edx, 0DEADBEAFh
            66 39 4C 18 18         // cmp [rax+rbx+18h], cx
            8B 44 18 28            // mov eax, [rax+rbx+28h]
            45 33 C9               // xor r9d, r9d
            44 8B C2               // mov r8d, edx
            48 8B CB               // mov rcx, rbx
            48 03 C3               // add rax, rbx
            FF D0                  // call rax
        }

	condition:
		( uint16(0)==0x5A4D and uint16( uint32(0x3c))==0x4550) and all of ($api*) and 1 of ($code*)
}
