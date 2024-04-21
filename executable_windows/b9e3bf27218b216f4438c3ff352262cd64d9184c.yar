import "pe"
import "time"

rule INDICATOR_SUSPICIOUS_EXE_SandboxSystemUUIDs
{
	meta:
		author = "ditekSHen"
		description = "Detects executables containing possible sandbox system UUIDs"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "00000000-0000-0000-0000-000000000000" ascii wide nocase
		$s2 = "00000000-0000-0000-0000-50E5493391EF" ascii wide nocase
		$s3 = "00000000-0000-0000-0000-AC1F6BD048FE" ascii wide nocase
		$s4 = "00000000-0000-0000-0000-AC1F6BD04972" ascii wide nocase
		$s5 = "00000000-0000-0000-0000-AC1F6BD04986" ascii wide nocase
		$s6 = "00000000-0000-0000-0000-AC1F6BD04D98" ascii wide nocase
		$s7 = "02AD9898-FA37-11EB-AC55-1D0C0A67EA8A" ascii wide nocase
		$s8 = "032E02B4-0499-05C3-0806-3C0700080009" ascii wide nocase
		$s9 = "03DE0294-0480-05DE-1A06-350700080009" ascii wide nocase
		$s10 = "050C3342-FADD-AEDF-EF24-C6454E1A73C9" ascii wide nocase
		$s11 = "05790C00-3B21-11EA-8000-3CECEF4400D0" ascii wide nocase
		$s12 = "07E42E42-F43D-3E1C-1C6B-9C7AC120F3B9" ascii wide nocase
		$s13 = "08C1E400-3C56-11EA-8000-3CECEF43FEDE" ascii wide nocase
		$s14 = "0934E336-72E4-4E6A-B3E5-383BD8E938C3" ascii wide nocase
		$s15 = "11111111-2222-3333-4444-555555555555" ascii wide nocase
		$s16 = "119602E8-92F9-BD4B-8979-DA682276D385" ascii wide nocase
		$s17 = "12204D56-28C0-AB03-51B7-44A8B7525250" ascii wide nocase
		$s18 = "12EE3342-87A2-32DE-A390-4C2DA4D512E9" ascii wide nocase
		$s19 = "1D4D3342-D6C4-710C-98A3-9CC6571234D5" ascii wide nocase
		$s20 = "2DD1B176-C043-49A4-830F-C623FFB88F3C" ascii wide nocase
		$s21 = "2E6FB594-9D55-4424-8E74-CE25A25E36B0" ascii wide nocase
		$s22 = "365B4000-3B25-11EA-8000-3CECEF44010C" ascii wide nocase
		$s23 = "38813342-D7D0-DFC8-C56F-7FC9DFE5C972" ascii wide nocase
		$s24 = "38AB3342-66B0-7175-0B23-F390B3728B78" ascii wide nocase
		$s25 = "3A9F3342-D1F2-DF37-68AE-C10F60BFB462" ascii wide nocase
		$s26 = "3F284CA4-8BDF-489B-A273-41B44D668F6D" ascii wide nocase
		$s27 = "3F3C58D1-B4F2-4019-B2A2-2A500E96AF2E" ascii wide nocase
		$s28 = "42A82042-3F13-512F-5E3D-6BF4FFFD8518" ascii wide nocase
		$s29 = "44B94D56-65AB-DC02-86A0-98143A7423BF" ascii wide nocase
		$s30 = "4729AEB0-FC07-11E3-9673-CE39E79C8A00" ascii wide nocase
		$s31 = "481E2042-A1AF-D390-CE06-A8F783B1E76A" ascii wide nocase
		$s32 = "48941AE9-D52F-11DF-BBDA-503734826431" ascii wide nocase
		$s33 = "49434D53-0200-9036-2500-369025000C65" ascii wide nocase
		$s34 = "49434D53-0200-9036-2500-369025003865" ascii wide nocase
		$s35 = "49434D53-0200-9036-2500-369025003AF0" ascii wide nocase
		$s36 = "49434D53-0200-9036-2500-36902500F022" ascii wide nocase
		$s37 = "49434D53-0200-9065-2500-65902500E439" ascii wide nocase
		$s38 = "4C4C4544-0050-3710-8058-CAC04F59344A" ascii wide nocase
		$s39 = "4CB82042-BA8F-1748-C941-363C391CA7F3" ascii wide nocase
		$s40 = "4D4DDC94-E06C-44F4-95FE-33A1ADA5AC27" ascii wide nocase
		$s41 = "4DC32042-E601-F329-21C1-03F27564FD6C" ascii wide nocase
		$s42 = "5BD24D56-789F-8468-7CDC-CAA7222CC121" ascii wide nocase
		$s43 = "5E3E7FE0-2636-4CB7-84F5-8D2650FFEC0E" ascii wide nocase
		$s44 = "5EBD2E42-1DB8-78A6-0EC3-031B661D5C57" ascii wide nocase
		$s45 = "60C83342-0A97-928D-7316-5F1080A78E72" ascii wide nocase
		$s46 = "63203342-0EB0-AA1A-4DF5-3FB37DBB0670" ascii wide nocase
		$s47 = "63FA3342-31C7-4E8E-8089-DAFF6CE5E967" ascii wide nocase
		$s48 = "6608003F-ECE4-494E-B07E-1C4615D1D93C" ascii wide nocase
		$s49 = "67E595EB-54AC-4FF0-B5E3-3DA7C7B547E3" ascii wide nocase
		$s50 = "6ECEAF72-3548-476C-BD8D-73134A9182C8" ascii wide nocase
		$s51 = "6F3CA5EC-BEC9-4A4D-8274-11168F640058" ascii wide nocase
		$s52 = "76122042-C286-FA81-F0A8-514CC507B250" ascii wide nocase
		$s53 = "777D84B3-88D1-451C-93E4-D235177420A7" ascii wide nocase
		$s54 = "79AF5279-16CF-4094-9758-F88A616D81B4" ascii wide nocase
		$s55 = "7AB5C494-39F5-4941-9163-47F54D6D5016" ascii wide nocase
		$s56 = "84FE3342-6C67-5FC6-5639-9B3CA3D775A1" ascii wide nocase
		$s57 = "88DC3342-12E6-7D62-B0AE-C80E578E7B07" ascii wide nocase
		$s58 = "8B4E8278-525C-7343-B825-280AEBCD3BCB" ascii wide nocase
		$s59 = "8DA62042-8B59-B4E3-D232-38B29A10964A" ascii wide nocase
		$s60 = "907A2A79-7116-4CB6-9FA5-E5A58C4587CD" ascii wide nocase
		$s61 = "921E2042-70D3-F9F1-8CBD-B398A21F89C6" ascii wide nocase
		$s62 = "96BB3342-6335-0FA8-BA29-E1BA5D8FEFBE" ascii wide nocase
		$s63 = "9921DE3A-5C1A-DF11-9078-563412000026" ascii wide nocase
		$s64 = "9961A120-E691-4FFE-B67B-F0E4115D5919" ascii wide nocase
		$s65 = "9C6D1742-046D-BC94-ED09-C36F70CC9A91" ascii wide nocase
		$s66 = "A15A930C-8251-9645-AF63-E45AD728C20C" ascii wide nocase
		$s67 = "A7721742-BE24-8A1C-B859-D7F8251A83D3" ascii wide nocase
		$s68 = "A9C83342-4800-0578-1EE8-BA26D2A678D2" ascii wide nocase
		$s69 = "ACA69200-3C4C-11EA-8000-3CECEF4401AA" ascii wide nocase
		$s70 = "ADEEEE9E-EF0A-6B84-B14B-B83A54AFC548" ascii wide nocase
		$s71 = "AF1B2042-4B90-0000-A4E4-632A1C8C7EB1" ascii wide nocase
		$s72 = "B1112042-52E8-E25B-3655-6A4F54155DBF" ascii wide nocase
		$s73 = "B6464A2B-92C7-4B95-A2D0-E5410081B812" ascii wide nocase
		$s74 = "BB233342-2E01-718F-D4A1-E7F69D026428" ascii wide nocase
		$s75 = "BB64E044-87BA-C847-BC0A-C797D1A16A50" ascii wide nocase
		$s76 = "BE784D56-81F5-2C8D-9D4B-5AB56F05D86E" ascii wide nocase
		$s77 = "C249957A-AA08-4B21-933F-9271BEC63C85" ascii wide nocase
		$s78 = "C6B32042-4EC3-6FDF-C725-6F63914DA7C7" ascii wide nocase
		$s79 = "C7D23342-A5D4-68A1-59AC-CF40F735B363" ascii wide nocase
		$s80 = "CC5B3F62-2A04-4D2E-A46C-AA41B7050712" ascii wide nocase
		$s81 = "CE352E42-9339-8484-293A-BD50CDC639A5" ascii wide nocase
		$s82 = "CEFC836C-8CB1-45A6-ADD7-209085EE2A57" ascii wide nocase
		$s83 = "CF1BE00F-4AAF-455E-8DCD-B5B09B6BFA8F" ascii wide nocase
		$s84 = "D2DC3342-396C-6737-A8F6-0C6673C1DE08" ascii wide nocase
		$s85 = "D7382042-00A0-A6F0-1E51-FD1BBF06CD71" ascii wide nocase
		$s86 = "D8C30328-1B06-4611-8E3C-E433F4F9794E" ascii wide nocase
		$s87 = "D9142042-8F51-5EFF-D5F8-EE9AE3D1602A" ascii wide nocase
		$s88 = "DBC22E42-59F7-1329-D9F2-E78A2EE5BD0D" ascii wide nocase
		$s89 = "DBCC3514-FA57-477D-9D1F-1CAF4CC92D0F" ascii wide nocase
		$s90 = "DD9C3342-FB80-9A31-EB04-5794E5AE2B4C" ascii wide nocase
		$s91 = "DEAEB8CE-A573-9F48-BD40-62ED6C223F20" ascii wide nocase
		$s92 = "E08DE9AA-C704-4261-B32D-57B2A3993518" ascii wide nocase
		$s93 = "EADD1742-4807-00A0-F92E-CCD933E9D8C1" ascii wide nocase
		$s94 = "EB16924B-FB6D-4FA1-8666-17B91F62FB37" ascii wide nocase
		$s95 = "F3988356-32F5-4AE1-8D47-FD3B8BAFBD4C" ascii wide nocase
		$s96 = "F5744000-3C78-11EA-8000-3CECEF43FEFE" ascii wide nocase
		$s97 = "FA8C2042-205D-13B0-FCB5-C5CC55577A35" ascii wide nocase
		$s98 = "FCE23342-91F1-EAFC-BA97-5AAE4509E173" ascii wide nocase
		$s99 = "FE455D1A-BE27-4BA4-96C8-967A6D3A9661" ascii wide nocase
		$s100 = "FE822042-A70C-D08B-F1D1-C207055A488F" ascii wide nocase
		$s101 = "FED63342-E0D6-C669-D53F-253D696D74DA" ascii wide nocase
		$s102 = "FF577B79-782E-0A4D-8568-B35A9B7EB76B" ascii wide nocase

	condition:
		uint16(0)==0x5a4d and 10 of them
}
