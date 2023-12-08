import "elf"

rule BlackMatter_Linux
{
	meta:
		author = "rivitna"
		family = "ransomware.blackmatter.linux"
		description = "BlackMatter ransomware Linux payload"
		severity = 10
		score = 100
		os = "linux"
		filetype = "executable"

	strings:
		$h0 = {                       // Loop:
                0F B6 10              // movzx edx, byte ptr [rax]
                84 D2                 // test  dl, dl
                74 19                 // jz    L1
                0F B6 34 0F           // movzx esi, byte ptr [rdi+rcx]
                40 38 F2              // cmp   dl, sil
                74 10                 // jz    L1
                48 83 C1 01           // add   rcx, 1
                31 F2                 // xor   edx, esi
                48 83 F9 20           // cmp   rcx, 20h
                88 10                 // mov   [rax], dl
                49 0F 44 C9           // cmovz rcx, r9
                                      // L1:
                48 83 C0 01           // add   rax, 1
                4C 39 C0              // cmp   rax, r8
                75 D7 }
		$h1 = { 44 42 46 44               // mov   [rsp+var_1], 44464244h
                C7 4? [1-2] 30 35 35 43   // mov   [rsp+var_2], 43353530h
                C7 4? [1-2] 2D 39 43 46   // mov   [rsp+var_3], 4643392Dh
                C7 4? [1-2] 32 2D 34 42   // mov   [rsp+var_4], 42342D32h
                C7 4? [1-2] 42 38 2D 39   // mov   [rsp+var_5], 392D3842h
                C7 4? [1-2] 30 38 45 2D   // mov   [rsp+var_6], 2D453830h
                C7 4? [1-2] 36 44 41 32   // mov   [rsp+var_7], 32414436h
                C7 4? [1-2] 32 33 32 31   // mov   [rsp+var_8], 31323332h
                C7 4? [1-2] 42 46 31 37 }

	condition:
		( uint32(0)==0x464C457F) and ((1 of ($h*)) or for any i in (0..elf.number_of_sections-2) : ((elf.sections[i].name==".app.version") and (elf.sections[i+1].name==".cfgETD")))
}
