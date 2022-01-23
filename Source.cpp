#include <iostream>
#include <string>
#include <algorithm>
#include <vector>
#include <Windows.h>
#include <TlHelp32.h>
#include <winver.h>
#include <psapi.h>
#include <sddl.h>
#include <wow64apiset.h>
#include <aclapi.h>
#include <lmcons.h>
#include <boost/property_tree/ptree.hpp>
#include <boost/property_tree/json_parser.hpp>


#pragma warning(disable:4996)
using namespace std;
boost::property_tree::ptree pt;
boost::property_tree::ptree all_processes;
boost::property_tree::ptree all_privileges;
boost::property_tree::ptree proc[1000];
boost::property_tree::ptree privileges[1000];
int process_count = 0;

struct privilege_struct
{
	string privilege;
	bool enable;
};

class SmartHandle
{
public:
	SmartHandle(HANDLE handle)
	{
		_handle = handle;
	}
	~SmartHandle()
	{
		if (_handle)
		{
			CloseHandle(_handle);
		}
	}

	operator bool()
	{
		return _handle != NULL;
	}
	operator HANDLE()
	{
		return _handle;
	}

	HANDLE handle()
	{
		return _handle;
	}
private:
	HANDLE _handle = NULL;
};



BOOL EnableDisablePrivilege(HANDLE token, const char* privilege, BOOL enable)
{
	BOOL ok = FALSE;
	LUID luid;
	if (LookupPrivilegeValueA(NULL, privilege, &luid))
	{
		TOKEN_PRIVILEGES tp;
		tp.PrivilegeCount = 1;
		tp.Privileges[0].Luid = luid;
		tp.Privileges[0].Attributes = 0;
		TOKEN_PRIVILEGES tpPrevious;
		DWORD cbPrevious = sizeof tpPrevious;
		AdjustTokenPrivileges(token, FALSE, &tp, sizeof tp, &tpPrevious, &cbPrevious);
		if (GetLastError() == ERROR_SUCCESS)
		{
			tpPrevious.PrivilegeCount = 1;
			tpPrevious.Privileges[0].Luid = luid;
			if (enable)
				tpPrevious.Privileges[0].Attributes |= SE_PRIVILEGE_ENABLED;
			else
				tpPrevious.Privileges[0].Attributes ^= SE_PRIVILEGE_ENABLED & tpPrevious.Privileges[0].Attributes;
			AdjustTokenPrivileges(token, FALSE, &tpPrevious, cbPrevious, NULL, NULL);
			ok = GetLastError() == ERROR_SUCCESS;
		}
	}
	return ok;
}

BOOL GetCurrentToken(HANDLE* token)
{
	BOOL ok = FALSE;
	if (!OpenThreadToken(GetCurrentThread(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, FALSE, token))
	{
		if (GetLastError() == ERROR_NO_TOKEN)
			if (ImpersonateSelf(SecurityImpersonation))
				if (OpenThreadToken(GetCurrentThread(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, FALSE, token))
					ok = TRUE;
	}
	else
		ok = TRUE;
	return ok;
}

BOOL ImpersonateProcess(HANDLE hProcess)
{
	BOOL ok = FALSE;
	HANDLE token;
	if (OpenProcessToken(hProcess, TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_ALL_ACCESS, &token))
	{
		if (ImpersonateLoggedOnUser(token))
			ok = TRUE;
	}
	return ok;
}

void ProcessName(PROCESSENTRY32 process_entry)
{
	wchar_t* process_name = process_entry.szExeFile;
	wstring ws(process_name);
	string process_name_str(ws.begin(), ws.end());
	proc[process_count].put("Process Name", process_name_str);
}

void ProcessDescription(PROCESSENTRY32 process_entry, SmartHandle current_process)
{
	if (process_entry.th32ProcessID == 0)
	{
		proc[process_count].put("Description", "");
		return;
	}
	wchar_t filename[_MAX_FNAME];
	if (K32GetModuleFileNameExW(current_process, NULL, filename, _MAX_FNAME))
	{
		int versionInfoSize = GetFileVersionInfoSize(filename, NULL);
		if (!versionInfoSize)
		{
			proc[process_count].put("Description", "");
			return;
		}
		auto versionInfo = new BYTE[versionInfoSize];
		std::unique_ptr<BYTE[]> versionInfo_automatic_cleanup(versionInfo);
		if (!GetFileVersionInfo(filename, NULL, versionInfoSize, versionInfo))
		{
			proc[process_count].put("Description", "");
			return;
		}

		struct LANGANDCODEPAGE
		{
			WORD wLanguage;
			WORD wCodePage;
		} *translationArray;

		UINT cbTranslate = 0;
		if (!VerQueryValue(versionInfo, L"\\VarFileInfo\\Translation", (LPVOID*)&translationArray, &cbTranslate))
		{
			proc[process_count].put("Description", "");
			return;
		}


		unsigned char fileDescriptionKey[256];
		sprintf((char*)fileDescriptionKey, "\\StringFileInfo\\%04x%04x\\FileDescription", translationArray[0].wLanguage, translationArray[0].wCodePage);
		unsigned char* fileDescription = NULL;
		UINT fileDescriptionSize;
		if (VerQueryValueA(versionInfo, (LPCSTR)fileDescriptionKey, (LPVOID*)&fileDescription, &fileDescriptionSize))
			proc[process_count].put("Description", fileDescription);
		else
			proc[process_count].put("Description", "");

	}
	else
		proc[process_count].put("Description", "");
}

void ProcessID(PROCESSENTRY32 process_entry)
{
	proc[process_count].put("PID", process_entry.th32ProcessID);
}

void Filename(PROCESSENTRY32 process_entry, SmartHandle current_process)
{
	if (process_entry.th32ProcessID == 0)
	{
		proc[process_count].put("Filename", "");
		return;
	}
	char filename[_MAX_FNAME] = { 0 };
	if (K32GetModuleFileNameExA(current_process, NULL, filename, _MAX_FNAME))
		proc[process_count].put("Filename", filename);
	else
		proc[process_count].put("Filename", "");
}

void ParentProcessID(PROCESSENTRY32 process_entry)
{
	proc[process_count].put("PPID", process_entry.th32ParentProcessID);
}

void ParentProcessName(PROCESSENTRY32 process_entry)
{
	SmartHandle parent_process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, process_entry.th32ParentProcessID);
	if (parent_process)
	{
		wchar_t parent_filename[_MAX_FNAME] = { 0 };
		K32GetModuleFileNameExW(parent_process, 0, parent_filename, _MAX_FNAME);
		wstring s(parent_filename);
		string parent_name(s.begin(), s.end());
		parent_name.erase(0, parent_name.find_last_of('\\') + 1);
		proc[process_count].put("Parent Name", parent_name);
	}
	else {
		proc[process_count].put("Parent Name", "");
	}
}

void Type(HANDLE current_process)
{
	BOOL process_type;
	if (current_process)
	{
		IsWow64Process(current_process, &process_type);
		if (process_type)
			proc[process_count].put("Process Type", "32-bit");
		else
			proc[process_count].put("Process Type", "64-bit");
	}
	else
		proc[process_count].put("Process Type", "");
}

void Platform_Lib(MODULEENTRY32 module_entry, HANDLE module_snap)
{
	bool NET = false;
	bool exe = true;
	string dll;
	while (Module32Next(module_snap, &module_entry))
	{
		wstring s(module_entry.szModule);
		string lib(s.begin(), s.end());
		if (!exe)
		{
			if (dll.empty())
				dll = lib;
			else
				dll = dll + " " + lib;
		}
		std::transform(lib.begin(), lib.end(), lib.begin(), ::toupper);
		string NET_lib = "MSCOREE.DLL";
		if (lib == NET_lib)
			NET = true;
		exe = false;
	}
	if (NET)
		proc[process_count].put("Platform", "CLR .NET");
	else
		proc[process_count].put("Platform", "Native");
	proc[process_count].put("Modules", dll);
}

void DEP_ASLR(SmartHandle current_process)
{
	PROCESS_MITIGATION_DEP_POLICY DEP_struct;
	PROCESS_MITIGATION_ASLR_POLICY ASLR_struct;
	if (GetProcessMitigationPolicy(current_process, ProcessDEPPolicy, (PVOID)&DEP_struct, sizeof(_PROCESS_MITIGATION_DEP_POLICY)))
	{
		if (DEP_struct.Enable)
			proc[process_count].put("DEP", "Enabled");
		else
			proc[process_count].put("DEP", "Disabled");
	}
	else
		proc[process_count].put("DEP", "");
	if (GetProcessMitigationPolicy(current_process, ProcessASLRPolicy, (PVOID)&ASLR_struct, sizeof(_PROCESS_MITIGATION_ASLR_POLICY)))
	{
		if (ASLR_struct.EnableBottomUpRandomization)
			proc[process_count].put("ASLR", "Enabled");
		else
			proc[process_count].put("ASLR", "Disabled");
	}
	else
		proc[process_count].put("ASLR", "");
}

void Owner_SID(HANDLE current_process)
{
	HANDLE token;
	DWORD token_len;
	PTOKEN_OWNER process_owner = (PTOKEN_OWNER)LocalAlloc(LPTR, sizeof(TOKEN_OWNER) + SECURITY_MAX_SID_SIZE);
	char* sid;
	if (OpenProcessToken(current_process, MAXIMUM_ALLOWED, &token))
	{
		if (GetTokenInformation(token, TokenOwner, process_owner, sizeof(TOKEN_OWNER) + SECURITY_MAX_SID_SIZE, &token_len))
		{
			char owner_name[_MAX_FNAME] = { 0 };
			char domain_name[_MAX_FNAME] = { 0 };
			DWORD owner_name_len = _MAX_FNAME;
			DWORD domain_name_len = _MAX_FNAME;
			SID_NAME_USE sid_type;
			if (LookupAccountSidA(NULL, process_owner->Owner, owner_name, &owner_name_len, domain_name, &domain_name_len, &sid_type))
			{
				if (ConvertSidToStringSidA(process_owner->Owner, &sid))
				{
					proc[process_count].put("Owner Name", owner_name);
					proc[process_count].put("SID", sid);
				}
				else
				{
					proc[process_count].put("Owner Name", "");
					proc[process_count].put("SID", "");
				}
			}
			else
			{
				proc[process_count].put("Owner Name", "");
				proc[process_count].put("SID", "");
			}
		}
		else
		{
			proc[process_count].put("Owner Name", "");
			proc[process_count].put("SID", "");
		}
	}
	else
	{
		proc[process_count].put("Owner Name", "");
		proc[process_count].put("SID", "");
	}
	LocalFree(process_owner);
}

int IntegrityLevel(int id)
{
	SmartHandle current_process = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, id);
	int integrity_num;
	HANDLE token;
	DWORD token_len;
	PTOKEN_MANDATORY_LABEL process_integrity = (PTOKEN_MANDATORY_LABEL)LocalAlloc(LPTR, sizeof(TOKEN_MANDATORY_LABEL) + SECURITY_MAX_SID_SIZE);
	if (OpenProcessToken(current_process, MAXIMUM_ALLOWED, &token))
	{
		if (GetTokenInformation(token, TokenIntegrityLevel, process_integrity, sizeof(TOKEN_MANDATORY_LABEL) + SECURITY_MAX_SID_SIZE, &token_len))
		{
			integrity_num = *GetSidSubAuthority(process_integrity->Label.Sid, (DWORD)(UCHAR)(*GetSidSubAuthorityCount(process_integrity->Label.Sid) - 1));
			if (integrity_num == SECURITY_MANDATORY_LOW_RID)
			{
				proc[process_count].put("Integrity Level", "Low Integrity Process");
				return 1;
			}
			else if (integrity_num >= SECURITY_MANDATORY_MEDIUM_RID && integrity_num < SECURITY_MANDATORY_HIGH_RID)
			{
				proc[process_count].put("Integrity Level", "Medium Integrity Process");
				return 2;
			}
			else if (integrity_num >= SECURITY_MANDATORY_HIGH_RID && integrity_num < SECURITY_MANDATORY_SYSTEM_RID)
			{
				proc[process_count].put("Integrity Level", "High Integrity Process");
				return 3;
			}
			else if (integrity_num >= SECURITY_MANDATORY_SYSTEM_RID)
			{
				proc[process_count].put("Integrity Level", "System Integrity Process");
				return 4;
			}
			else
			{
				proc[process_count].put("Integrity Level", "Untrusted Integrity Process");
				return 0;
			}
		}
		else
		{
			proc[process_count].put("Integrity Level", "");
			return -1;
		}
	}
	else
	{
		proc[process_count].put("Integrity Level", "");
		return -1;
	}
	LocalFree(process_integrity);
}

void SetIntegrityLevel(int id, int level)
{
	if (IntegrityLevel(id) <= level) return;
	HANDLE current_token;
	if (GetCurrentToken(&current_token))
	{
		const BOOL debug_set = EnableDisablePrivilege(current_token, "SeDebugPrivilege", TRUE);
		const HANDLE process = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, id);
		if (process)
		{
			if (EnableDisablePrivilege(current_token, "SeImpersonatePrivilege", TRUE))
			{
				if (ImpersonateProcess(process))
				{
					HANDLE token;
					DWORD token_len;
					const wchar_t levels[5][20] =
					{
						L"S-1-16-0", L"S-1-16-4096", L"S-1-16-8192", L"S-1-16-12288", L"S-1-16-16384"
					};
					PSID NewIntegrity = NULL;
					PTOKEN_MANDATORY_LABEL process_integrity = (PTOKEN_MANDATORY_LABEL)LocalAlloc(LPTR, sizeof(TOKEN_MANDATORY_LABEL) + SECURITY_MAX_SID_SIZE);
					PTOKEN_MANDATORY_LABEL session_id = (PTOKEN_MANDATORY_LABEL)LocalAlloc(LPTR, sizeof(TOKEN_MANDATORY_LABEL) + SECURITY_MAX_SID_SIZE);
					ConvertStringSidToSidW(levels[level], &NewIntegrity);
					process_integrity->Label.Sid = NewIntegrity;
					process_integrity->Label.Attributes = SE_PRIVILEGE_ENABLED;
					if (OpenProcessToken(process, MAXIMUM_ALLOWED, &token))
					{
						SetTokenInformation(token, TokenIntegrityLevel, process_integrity, sizeof(TOKEN_MANDATORY_LABEL) + GetLengthSid(NewIntegrity));

					}
					LocalFree(process_integrity);
				}
				EnableDisablePrivilege(current_token, "SeImpersonatePrivilege", FALSE);
			}

		}
		if (debug_set)
			EnableDisablePrivilege(current_token, "SeDebugPrivilege", FALSE);
	}
}

void Privileges(HANDLE current_process)
{
	HANDLE token;
	DWORD token_len;
	DWORD size;
	if (OpenProcessToken(current_process, MAXIMUM_ALLOWED, &token))
	{
		if (!GetTokenInformation(token, TokenPrivileges, NULL, 0, &size) && GetLastError() == ERROR_INSUFFICIENT_BUFFER)
		{
			PTOKEN_PRIVILEGES token_privilege = (PTOKEN_PRIVILEGES)LocalAlloc(LPTR, sizeof(TOKEN_PRIVILEGES) * size);
			if (token_privilege != NULL && GetTokenInformation(token, TokenPrivileges, token_privilege, size, &size))
			{
				for (int i = 0; i < token_privilege->PrivilegeCount; i++)
				{
					char name[64];
					DWORD NAME_SIZE = sizeof name;
					LookupPrivilegeNameA(0, &token_privilege->Privileges[i].Luid, name, &NAME_SIZE);
					BOOL result;
					PRIVILEGE_SET privilege_set;
					privilege_set.PrivilegeCount = 1;
					privilege_set.Control = PRIVILEGE_SET_ALL_NECESSARY;
					privilege_set.Privilege[0].Luid = token_privilege->Privileges[i].Luid;
					privilege_set.Privilege[0].Attributes = SE_PRIVILEGE_ENABLED;
					PrivilegeCheck(token, &privilege_set, &result);
					string priv_name = name;
					if (result)
						privileges[process_count].put(name, "Enabled");
					else
						privileges[process_count].put(name, "Disabled");
				}
				proc[process_count].add_child("Privileges", privileges[process_count]);
			}
			else
				proc[process_count].put("Privileges", "");
			LocalFree(token_privilege);
		}
		else
			proc[process_count].put("Privileges", "");
	}
	else
		proc[process_count].put("Privileges", "");
}

void PrivilegesError(vector<privilege_struct> privilege_list)
{
	for (int i = 0; i < privilege_list.size(); i++)
		all_privileges.put(privilege_list[i].privilege, "Error");
}

void SetPrivilege(int id, int level, vector<privilege_struct> privilege_list)
{
	HANDLE current_token;
	if (GetCurrentToken(&current_token))
	{
		const BOOL debug_set = EnableDisablePrivilege(current_token, "SeDebugPrivilege", TRUE);
		const HANDLE process = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, id);
		if (process)
		{
			if (EnableDisablePrivilege(current_token, "SeImpersonatePrivilege", TRUE))
			{
				HANDLE integrity_token, privilege_token;
				DWORD token_len;
				if (OpenProcessToken(process, TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &privilege_token))
				{
					for (int i = 0; i < privilege_list.size(); i++)
					{
						if (EnableDisablePrivilege(privilege_token, privilege_list[i].privilege.c_str(), privilege_list[i].enable))
							all_privileges.put(privilege_list[i].privilege, "Success");
						else
							all_privileges.put(privilege_list[i].privilege, "Error");
					}
				}
				else
					PrivilegesError(privilege_list);
				const wchar_t levels[5][20] =
				{
					L"S-1-16-0", L"S-1-16-4096", L"S-1-16-8192", L"S-1-16-12288", L"S-1-16-16384"
				};
				PSID NewIntegrity = NULL;
				PTOKEN_MANDATORY_LABEL process_integrity = (PTOKEN_MANDATORY_LABEL)LocalAlloc(LPTR, sizeof(TOKEN_MANDATORY_LABEL) + SECURITY_MAX_SID_SIZE);
				PTOKEN_MANDATORY_LABEL session_id = (PTOKEN_MANDATORY_LABEL)LocalAlloc(LPTR, sizeof(TOKEN_MANDATORY_LABEL) + SECURITY_MAX_SID_SIZE);
				ConvertStringSidToSidW(levels[level], &NewIntegrity);
				process_integrity->Label.Sid = NewIntegrity;
				process_integrity->Label.Attributes = SE_PRIVILEGE_ENABLED;
				if (OpenProcessToken(process, MAXIMUM_ALLOWED, &integrity_token))
				{
					SetTokenInformation(integrity_token, TokenIntegrityLevel, process_integrity, sizeof(TOKEN_MANDATORY_LABEL) + GetLengthSid(NewIntegrity));
					if (IntegrityLevel(id) == level)
						all_privileges.put("Integrity", "Success");
					else
						all_privileges.put("Integrity", "Error");

				}
				else
					all_privileges.put("Integrity", "Error");
				LocalFree(process_integrity);

				EnableDisablePrivilege(current_token, "SeImpersonatePrivilege", FALSE);
			}
			else
			{
				PrivilegesError(privilege_list);
				all_privileges.put("Integrity", "Error");
			}
		}
		else
		{
			PrivilegesError(privilege_list);
			all_privileges.put("Integrity", "Error");
		}
		if (debug_set)
			EnableDisablePrivilege(current_token, "SeDebugPrivilege", FALSE);
	}
}

int FileIntegrityLevel(LPCSTR filename)
{
	DWORD integrity_level = SECURITY_MANDATORY_UNTRUSTED_RID;
	PSECURITY_DESCRIPTOR security_descriptor = NULL;
	PACL acl = 0;
	if (GetNamedSecurityInfoA(filename, SE_FILE_OBJECT, LABEL_SECURITY_INFORMATION, 0, 0, 0, &acl, &security_descriptor) == ERROR_SUCCESS)
	{
		if (0 != acl && 0 < acl->AceCount)
		{
			SYSTEM_MANDATORY_LABEL_ACE* ace = 0;
			if (GetAce(acl, 0, reinterpret_cast<void**>(&ace)))
			{
				SID* sid = reinterpret_cast<SID*>(&ace->SidStart);
				integrity_level = sid->SubAuthority[0];
			}
		}

		PWSTR string_sd;
		ULONG string_sd_len = 0;

		ConvertSecurityDescriptorToStringSecurityDescriptorW(security_descriptor, SDDL_REVISION_1, LABEL_SECURITY_INFORMATION, &string_sd, &string_sd_len);

		if (security_descriptor)
			LocalFree(security_descriptor);
	}
	int x = GetLastError();
	if (integrity_level == 0x0000)
		return 0;
	else if (integrity_level == 0x1000)
		return 1;
	else if (integrity_level == 0x2000)
		return 2;
	else if (integrity_level == 0x3000)
		return 3;
	else if (integrity_level == 0x4000)
		return 4;
	else
		return -1;
}

bool SetFileIntegrityLevel(int level, const char* filename)
{
	LPCSTR integrity = NULL;
	if (level == 0)
		integrity = "S:(ML;;NR;;;LW)";
	else if (level == 1)
		integrity = "S:(ML;;NR;;;ME)";
	else if (level == 2)
		integrity = "S:(ML;;NR;;;HI)";

	DWORD error_code = ERROR_SUCCESS;
	PSECURITY_DESCRIPTOR security_descriptor = NULL;

	PACL sacl = NULL;
	BOOL sacl_present = FALSE;
	BOOL sacl_defaulted = FALSE;

	if (ConvertStringSecurityDescriptorToSecurityDescriptorA(integrity, SDDL_REVISION_1, &security_descriptor, NULL))
	{
		if (GetSecurityDescriptorSacl(security_descriptor, &sacl_present, &sacl, &sacl_defaulted))
		{
			error_code = SetNamedSecurityInfoA((LPSTR)filename, SE_FILE_OBJECT, LABEL_SECURITY_INFORMATION, NULL, NULL, NULL, sacl);

			if (error_code == ERROR_SUCCESS)
				return true;
		}
		LocalFree(security_descriptor);
		return false;
	}
	return false;
}

void ACL_Owner(LPCSTR filename)
{
	PACL dacl;
	PACL sacl;
	PSID sidowner = NULL;
	PSID sidgroup = NULL;
	PSECURITY_DESCRIPTOR sec;
	DWORD owner_name_len = UNLEN;
	DWORD domain_name_len = UNLEN;
	LPSTR owner_name = (LPSTR)LocalAlloc(GMEM_FIXED, owner_name_len);
	LPSTR domain_name = (LPSTR)LocalAlloc(GMEM_FIXED, domain_name_len);
	SID_NAME_USE peUse;
	LPVOID ace;
	GetNamedSecurityInfoA(filename, SE_FILE_OBJECT, OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION, &sidowner, &sidgroup, &dacl, NULL, &sec);
	LookupAccountSidA(NULL, sidowner, owner_name, &owner_name_len, domain_name, &domain_name_len, &peUse);
	cout << " Owner: " << owner_name << endl;
	SID* sid;
	unsigned long mask;
	for (int i = 0; i < (*dacl).AceCount; i++)
	{
		GetAce(dacl, i, &ace);
		ACCESS_ALLOWED_ACE* ace_2 = (ACCESS_ALLOWED_ACE*)ace;
		owner_name_len = UNLEN;
		domain_name_len = UNLEN;
		if (((ACCESS_ALLOWED_ACE*)ace)->Header.AceType == ACCESS_ALLOWED_ACE_TYPE)
		{
			sid = (SID*)&((ACCESS_ALLOWED_ACE*)ace)->SidStart;
			LookupAccountSidA(NULL, sid, owner_name, &owner_name_len, domain_name, &domain_name_len, &peUse);
			mask = ((ACCESS_ALLOWED_ACE*)ace)->Mask;
			cout << owner_name << endl;
		}
		else if (((ACCESS_DENIED_ACE*)ace)->Header.AceType == ACCESS_DENIED_ACE_TYPE)
		{
			sid = (SID*)&((ACCESS_DENIED_ACE*)ace)->SidStart;
			LookupAccountSidA(NULL, sid, owner_name, &owner_name_len, domain_name, &domain_name_len, &peUse);
			mask = ((ACCESS_DENIED_ACE*)ace)->Mask;
			cout << owner_name << endl;
		}
		if (DELETE & ace_2->Mask)
			cout << " Delete" << endl;
		if (FILE_GENERIC_READ & ace_2->Mask)
			cout << " File_Generic_Read" << endl;
		if (FILE_GENERIC_WRITE & ace_2->Mask)
			cout << " File_Generic_Write" << endl;
		if (FILE_GENERIC_EXECUTE & ace_2->Mask)
			cout << " File_Generic_Execute" << endl;
		if (GENERIC_READ & ace_2->Mask)
			cout << " Generic_Read" << endl;
		if (GENERIC_WRITE & ace_2->Mask)
			cout << " Generic_Write" << endl;
		if (GENERIC_EXECUTE & ace_2->Mask)
			cout << " Generic_Execute" << endl;
		if (GENERIC_ALL & ace_2->Mask)
			cout << " Generic_All" << endl;
		if (READ_CONTROL & ace_2->Mask)
			cout << " Read_Control" << endl;
		if (WRITE_DAC & ace_2->Mask)
			cout << " Write_DAC" << endl;
		if (WRITE_OWNER & ace_2->Mask)
			cout << " Write_Owner" << endl;
		if (SYNCHRONIZE & ace_2->Mask)
			cout << " Synchronize" << endl;
		cout << endl;
	}
}

PSID SetSid(const char* username)
{
	LPCSTR wszAccName = username;
	LPSTR wszDomainName = (LPSTR)GlobalAlloc(GPTR, sizeof(TCHAR) * 1024);
	DWORD cchDomainName = 1024;
	SID_NAME_USE eSidType;
	LPTSTR sidstring;
	char sid_buffer[1024];
	DWORD cbSid = 1024;
	PSID sid = (PSID)LocalAlloc(LPTR, sizeof(SID) + +SECURITY_MAX_SID_SIZE);
	if (LookupAccountNameA(NULL, wszAccName, sid, &cbSid, wszDomainName, &cchDomainName, &eSidType))
		return sid;
}

void SetACL(const char* username, const char* filename, SID_IDENTIFIER_AUTHORITY level)
{
	DWORD dwRes = 0, dwDisposition;
	PSID sid = SetSid(username);
	PACL pACL = NULL;
	PSECURITY_DESCRIPTOR pSD = NULL;
	EXPLICIT_ACCESS ea;
	SID_IDENTIFIER_AUTHORITY SIDAuth = level;
	SECURITY_ATTRIBUTES sa;
	LONG lRes;
	HKEY hkSub = NULL;
	PACL pOldDACL = NULL, pNewDACL = NULL;
	dwRes = GetNamedSecurityInfoA(filename, SE_FILE_OBJECT, DACL_SECURITY_INFORMATION, NULL, NULL, &pOldDACL, NULL, &pSD);
	ZeroMemory(&ea, sizeof(EXPLICIT_ACCESS));
	ea.grfAccessPermissions = DELETE;
	ea.grfAccessMode = SET_ACCESS;
	ea.grfInheritance = NO_INHERITANCE;
	ea.Trustee.TrusteeForm = TRUSTEE_IS_SID;
	ea.Trustee.TrusteeType = TRUSTEE_IS_WELL_KNOWN_GROUP;
	ea.Trustee.ptstrName = (LPTSTR)sid;
	dwRes = SetEntriesInAclW(1, &ea, pOldDACL, &pNewDACL);
	dwRes = SetNamedSecurityInfoA((LPSTR)filename, SE_FILE_OBJECT, DACL_SECURITY_INFORMATION, NULL, NULL, pNewDACL, NULL);
}

void SetOwner(const char* username, const char* filename, SID_IDENTIFIER_AUTHORITY level)
{
	HANDLE token;
	PSID sid = SetSid(username);
	if (!sid)
	{
		all_privileges.put("Owner", "Wrong Name");
		return;
	}
	OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &token);
	TOKEN_PRIVILEGES tp;
	tp.PrivilegeCount = 1;
	tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
	LookupPrivilegeValueA(NULL, "SeTakeOwnershipPrivilege", &tp.Privileges[0].Luid);
	AdjustTokenPrivileges(token, NULL, &tp, sizeof(tp), NULL, NULL);
	LookupPrivilegeValueA(NULL, "SeRestorePrivilege", &tp.Privileges[0].Luid);
	AdjustTokenPrivileges(token, NULL, &tp, sizeof(tp), NULL, NULL);
	PSID owner;
	SID_IDENTIFIER_AUTHORITY SIDAuth = level;
	if (SetNamedSecurityInfoA((LPSTR)filename, SE_FILE_OBJECT, OWNER_SECURITY_INFORMATION, sid, NULL, NULL, NULL) == ERROR_SUCCESS)
		all_privileges.put("Owner", "Success");
	else
		all_privileges.put("Owner", "Error");
}

int main(int argc, char* argv[])
{
	vector<string> arguments;
	vector<privilege_struct> privilege_list;
	for (int i = 0; i < argc; i++)
		arguments.push_back(argv[i]);
	if (arguments[1] == "all_processes")
	{
		PROCESSENTRY32 process_entry;
		MODULEENTRY32 module_entry;
		process_entry.dwSize = sizeof(PROCESSENTRY32);
		module_entry.dwSize = sizeof(MODULEENTRY32);
		SmartHandle process_snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
		while (Process32Next(process_snap, &process_entry))
		{
			SmartHandle module_snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, process_entry.th32ProcessID);
			SmartHandle current_process = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, process_entry.th32ProcessID);
			ProcessName(process_entry);
			ProcessDescription(process_entry, current_process);
			ProcessID(process_entry);
			Filename(process_entry, current_process);
			ParentProcessID(process_entry);
			ParentProcessName(process_entry);
			Owner_SID(current_process);
			Type(current_process);
			DEP_ASLR(current_process);
			Platform_Lib(module_entry, module_snap);
			IntegrityLevel(process_entry.th32ProcessID);
			Privileges(current_process);
			process_count++;
		}
		for (int i = 0; i < process_count; i++)
			all_processes.push_back(std::make_pair("", proc[i]));
		pt.add_child("Processes", all_processes);
		write_json("D:\\Visual Studio Projects\\processes.json", pt);
		system("powershell -command \"Get-Content -path \'D:\\Visual Studio Projects\\processes.json\' | Set-Content -Encoding utf8 \'D:\\Visual Studio Projects\\processes_utf8.json\'\"");
		return 0;
	}
	else if (arguments[1] == "set_priv")
	{
		privilege_struct priv;
		for (int i = 4; i < argc; i++)
		{
			priv.privilege = arguments[i].substr(0, arguments[i].length() - 2);
			if (arguments[i].back() == '0')
				priv.enable = false;
			else if (arguments[i].back() == '1')
				priv.enable = true;
			privilege_list.push_back(priv);
		}
		SetPrivilege(stoi(arguments[2]), stoi(arguments[3]), privilege_list);

		pt.add_child("Log", all_privileges);
		/*write_json("D:\\Visual Studio Projects\\log.json", pt);*/
		return 0;
	}
	else if (arguments[1] == "set_owner")
	{
		int x = FileIntegrityLevel(arguments[2].c_str());
		SetOwner(arguments[3].c_str(), arguments[2].c_str(), SECURITY_NT_AUTHORITY);
		if (SetFileIntegrityLevel(stoi(arguments[4]), arguments[2].c_str()))
			all_privileges.put("Integrity", "Success");
		else
			all_privileges.put("Integrity", "Error");
		pt.add_child("Log", all_privileges);
		/*write_json("D:\\Visual Studio Projects\\log.json", pt);*/
		return 0;
	}
}