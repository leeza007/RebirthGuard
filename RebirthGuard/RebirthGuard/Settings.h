
/********************************************
*											*
*	RebirthGuard/Settings.h - chztbby		*
*											*
********************************************/



//-----------------------------------------------------------------
//
//	RebirthGuard Options
//
//-----------------------------------------------------------------

#define DISABLE					0x00000000
#define ENABLE					0x00000001
#define		LOG					0x00000002	
#define		POPUP				0x00000004
#define		KILL				0x00000008

//-----------------------------------------------------------------

#define PROCESS_POLICY			ENABLE
#define		MS_SIGNED_ONLY		DISABLE
#define		POLICY				PROCESS_CREATION_MITIGATION_POLICY_DEP_ENABLE\
								| PROCESS_CREATION_MITIGATION_POLICY_DEP_ATL_THUNK_ENABLE\
								| PROCESS_CREATION_MITIGATION_POLICY_SEHOP_ENABLE\
								| PROCESS_CREATION_MITIGATION_POLICY_FORCE_RELOCATE_IMAGES_ALWAYS_ON_REQ_RELOCS\
								| PROCESS_CREATION_MITIGATION_POLICY_HEAP_TERMINATE_ALWAYS_ON\
								| PROCESS_CREATION_MITIGATION_POLICY_BOTTOM_UP_ASLR_ALWAYS_ON\
								| PROCESS_CREATION_MITIGATION_POLICY_HIGH_ENTROPY_ASLR_ALWAYS_ON\
								| PROCESS_CREATION_MITIGATION_POLICY_STRICT_HANDLE_CHECKS_ALWAYS_ON\
								| PROCESS_CREATION_MITIGATION_POLICY_EXTENSION_POINT_DISABLE_ALWAYS_ON\
								| PROCESS_CREATION_MITIGATION_POLICY_CONTROL_FLOW_GUARD_ALWAYS_ON\
								| PROCESS_CREATION_MITIGATION_POLICY_FONT_DISABLE_ALWAYS_ON\
								| PROCESS_CREATION_MITIGATION_POLICY_IMAGE_LOAD_NO_REMOTE_ALWAYS_ON\
								| PROCESS_CREATION_MITIGATION_POLICY_IMAGE_LOAD_NO_LOW_LABEL_ALWAYS_ON\
								| PROCESS_CREATION_MITIGATION_POLICY_IMAGE_LOAD_PREFER_SYSTEM32_ALWAYS_ON\
								| PROCESS_CREATION_MITIGATION_POLICY2_STRICT_CONTROL_FLOW_GUARD_ALWAYS_ON\
								| PROCESS_CREATION_MITIGATION_POLICY2_MODULE_TAMPERING_PROTECTION_ALWAYS_ON\
								| PROCESS_CREATION_MITIGATION_POLICY2_RESTRICT_INDIRECT_BRANCH_PREDICTION_ALWAYS_ON

#define FILE_CHECK				ENABLE | LOG | POPUP | KILL

#define THREAD_CHECK			ENABLE | LOG | POPUP | KILL

#define MEM_INFO_CHECK			ENABLE | LOG | POPUP

#define CRC_CHECK				ENABLE | LOG | POPUP | KILL
#define		USING_MIRROR_VIEW	ENABLE

#define ANTI_DLL_INJECTION		ENABLE | LOG | POPUP | KILL

#define ANTI_DEBUGGING			ENABLE | LOG | POPUP | KILL

#define EXCEPTION_HANDLING		ENABLE | LOG | POPUP

#define SECTION_LIST_ALLOC		0x010000000000
#define SECTION_LIST_SIZE		0x10000

#define XOR_KEY					0xAD


//-----------------------------------------------------------------
//	Whitelist (Remapping)
//-----------------------------------------------------------------
static CONST WCHAR* Whitelist_Rebirth[] =
{
	L"nvoglv64.dll",
	L""
};


//-----------------------------------------------------------------
//	Whitelist (File CheckSum)
//-----------------------------------------------------------------
static CONST WCHAR* Whitelist_FileCheck[] =
{
	L"glew32.dll",
	L"assimp-vc140-mt.dll",
	L"freetype.dll",
	L"fmod64.dll",
	L""
};