//! Coarse capability classification for imported function names.
//!
//! Given the list of imports a function calls (resolved via the
//! analyzer's `imported_callees` set), this module maps each
//! import name to a small set of "capability" tags:
//!
//! * `calls_alloc` — heap / virtual memory allocation
//! * `calls_memcpy` — block memory operations (copy / move / set)
//! * `calls_network` — sockets, HTTP, DNS, generally any byte
//!   that ends up on a wire
//! * `calls_filesystem` — file create / read / write / delete
//! * `calls_registry` — Windows registry access
//! * `calls_process` — process / thread creation, injection-shaped
//!   APIs (OpenProcess, CreateRemoteThread, WriteProcessMemory)
//! * `calls_crypto` — CryptoAPI, BCrypt, NCrypt families
//! * `calls_loader` — dynamic loading (LoadLibrary, GetProcAddress)
//! * `calls_debug` — debugger / anti-debugger surface
//!
//! Tags are deliberately coarse — they're meant to be glanceable in
//! the JSON output, not exhaustive. Unknown imports produce no tag.

use std::collections::BTreeSet;

/// Returns the set of capability tags for an import name. An
/// import that doesn't match any category yields an empty set.
pub fn tags_for_import(name: &str) -> &'static [&'static str] {
    let lc_first_char = name
        .chars()
        .next()
        .map(|c| c.to_ascii_lowercase())
        .unwrap_or('\0');
    // Quick early-out for non-alphanumeric leading chars (avoids
    // doing an ASCII-lowercase comparison against the whole table
    // for entries we know don't match).
    if !lc_first_char.is_ascii_alphabetic() && lc_first_char != '_' {
        return &[];
    }

    // Match against a lowercase view of `name`. Allocate only when
    // the name contains uppercase letters.
    let buf;
    let lc: &str = if name.bytes().any(|b| b.is_ascii_uppercase()) {
        buf = name.to_ascii_lowercase();
        &buf
    } else {
        name
    };

    // ---- allocation ----
    if matches!(
        lc,
        "malloc"
            | "calloc"
            | "realloc"
            | "free"
            | "heapalloc"
            | "heapfree"
            | "heaprealloc"
            | "heapcreate"
            | "heapdestroy"
            | "rtlallocateheap"
            | "rtlfreeheap"
            | "rtlreallocateheap"
            | "localalloc"
            | "localfree"
            | "localrealloc"
            | "globalalloc"
            | "globalfree"
            | "globalrealloc"
            | "virtualalloc"
            | "virtualallocex"
            | "virtualfree"
            | "virtualfreeex"
    ) {
        return &["calls_alloc"];
    }

    // ---- memory ops ----
    if matches!(
        lc,
        "memcpy"
            | "memmove"
            | "memset"
            | "memcmp"
            | "rtlmovememory"
            | "rtlcopymemory"
            | "rtlfillmemory"
            | "rtlzeromemory"
            | "rtlcomparememory"
            | "strcpy"
            | "strncpy"
            | "strcpy_s"
            | "strncpy_s"
            | "lstrcpya"
            | "lstrcpyw"
            | "lstrcpyna"
    ) {
        return &["calls_memcpy"];
    }

    // ---- network ----
    if matches!(
        lc,
        "socket"
            | "bind"
            | "listen"
            | "accept"
            | "connect"
            | "send"
            | "sendto"
            | "recv"
            | "recvfrom"
            | "closesocket"
            | "shutdown"
            | "wsastartup"
            | "wsacleanup"
            | "wsagetlasterror"
            | "gethostbyname"
            | "gethostname"
            | "getaddrinfo"
            | "freeaddrinfo"
            | "internetopena"
            | "internetopenw"
            | "internetopenurla"
            | "internetopenurlw"
            | "internetreadfile"
            | "internetwritefile"
            | "internetclosehandle"
            | "internetconnecta"
            | "internetconnectw"
            | "httpopenrequesta"
            | "httpopenrequestw"
            | "httpsendrequesta"
            | "httpsendrequestw"
            | "winhttpopen"
            | "winhttpconnect"
            | "winhttpopenrequest"
            | "winhttpsendrequest"
    ) {
        return &["calls_network"];
    }

    // ---- filesystem ----
    if matches!(
        lc,
        "createfilea"
            | "createfilew"
            | "openfile"
            | "deletefilea"
            | "deletefilew"
            | "movefilea"
            | "movefilew"
            | "movefileexa"
            | "movefileexw"
            | "copyfilea"
            | "copyfilew"
            | "writefile"
            | "readfile"
            | "writefileex"
            | "readfileex"
            | "setfilepointer"
            | "setfilepointerex"
            | "getfilesize"
            | "getfilesizeex"
            | "getfiletype"
            | "getfileattributesa"
            | "getfileattributesw"
            | "setfileattributesa"
            | "setfileattributesw"
            | "findfirstfilea"
            | "findfirstfilew"
            | "findnextfilea"
            | "findnextfilew"
            | "findclose"
            | "createdirectorya"
            | "createdirectoryw"
            | "removedirectorya"
            | "removedirectoryw"
            | "fopen"
            | "fopen_s"
            | "fclose"
            | "fread"
            | "fwrite"
            | "open"
            | "close"
            | "read"
            | "write"
            | "stat"
            | "fstat"
            | "lstat"
            | "unlink"
            | "rename"
    ) {
        return &["calls_filesystem"];
    }

    // ---- registry ----
    if matches!(
        lc,
        "regopenkeya"
            | "regopenkeyw"
            | "regopenkeyexa"
            | "regopenkeyexw"
            | "regclosekey"
            | "regqueryvaluea"
            | "regqueryvaluew"
            | "regqueryvalueexa"
            | "regqueryvalueexw"
            | "regsetvaluea"
            | "regsetvaluew"
            | "regsetvalueexa"
            | "regsetvalueexw"
            | "regdeletevaluea"
            | "regdeletevaluew"
            | "regdeletekeya"
            | "regdeletekeyw"
            | "regdeletekeyexa"
            | "regdeletekeyexw"
            | "regcreatekeya"
            | "regcreatekeyw"
            | "regcreatekeyexa"
            | "regcreatekeyexw"
            | "regenumkeya"
            | "regenumkeyw"
            | "regenumkeyexa"
            | "regenumkeyexw"
            | "regenumvaluea"
            | "regenumvaluew"
    ) {
        return &["calls_registry"];
    }

    // ---- process / injection-shape ----
    if matches!(
        lc,
        "createprocessa"
            | "createprocessw"
            | "createprocessasusera"
            | "createprocessasuserw"
            | "openprocess"
            | "terminateprocess"
            | "exitprocess"
            | "createthread"
            | "createremotethread"
            | "createremotethreadex"
            | "terminatethread"
            | "openthread"
            | "suspendthread"
            | "resumethread"
            | "writeprocessmemory"
            | "readprocessmemory"
            | "virtualprotectex"
            | "virtualallocex"
            | "ntcreatethreadex"
            | "rtlcreateuserthread"
            | "queueuserapc"
            | "ntqueueapcthread"
            | "setthreadcontext"
            | "getthreadcontext"
    ) {
        return &["calls_process"];
    }

    // ---- crypto ----
    if matches!(
        lc,
        "cryptacquirecontexta"
            | "cryptacquirecontextw"
            | "cryptcreatehash"
            | "crypthashdata"
            | "cryptderivekey"
            | "cryptencrypt"
            | "cryptdecrypt"
            | "cryptgenrandom"
            | "cryptreleasecontext"
            | "cryptdestroyhash"
            | "cryptdestroykey"
            | "cryptimportkey"
            | "cryptexportkey"
            | "bcryptopenalgorithmprovider"
            | "bcryptclosealgorithmprovider"
            | "bcryptcreatehash"
            | "bcrypthashdata"
            | "bcryptdecrypt"
            | "bcryptencrypt"
            | "bcryptgenrandom"
            | "ncryptopenstorageprovider"
            | "ncryptopenkey"
    ) {
        return &["calls_crypto"];
    }

    // ---- loader ----
    if matches!(
        lc,
        "loadlibrarya"
            | "loadlibraryw"
            | "loadlibraryexa"
            | "loadlibraryexw"
            | "freelibrary"
            | "getprocaddress"
            | "getmodulehandlea"
            | "getmodulehandlew"
            | "getmodulehandleexa"
            | "getmodulehandleexw"
            | "ldrloaddll"
            | "ldrgetprocedureaddress"
            | "dlopen"
            | "dlsym"
            | "dlclose"
    ) {
        return &["calls_loader"];
    }

    // ---- debug / anti-debug ----
    if matches!(
        lc,
        "isdebuggerpresent"
            | "checkremotedebuggerpresent"
            | "ntqueryinformationprocess"
            | "outputdebugstringa"
            | "outputdebugstringw"
            | "debugbreak"
            | "debugactiveprocess"
            | "waitfordebugevent"
            | "continuedebugevent"
            | "setunhandledexceptionfilter"
            | "unhandledexceptionfilter"
            | "addvectoredexceptionhandler"
            | "removevectoredexceptionhandler"
    ) {
        return &["calls_debug"];
    }

    &[]
}

/// Collect the deduplicated capability tags for a set of import
/// names.
pub fn tags_for_imports<I: IntoIterator<Item = N>, N: AsRef<str>>(names: I) -> Vec<String> {
    let mut out: BTreeSet<&'static str> = BTreeSet::new();
    for name in names {
        for tag in tags_for_import(name.as_ref()) {
            out.insert(tag);
        }
    }
    out.into_iter().map(String::from).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tags_simple_imports() {
        assert_eq!(tags_for_import("HeapAlloc"), &["calls_alloc"]);
        assert_eq!(tags_for_import("memcpy"), &["calls_memcpy"]);
        assert_eq!(tags_for_import("WSAStartup"), &["calls_network"]);
        assert_eq!(tags_for_import("CreateFileA"), &["calls_filesystem"]);
        assert_eq!(tags_for_import("RegOpenKeyExA"), &["calls_registry"]);
        assert_eq!(tags_for_import("CreateRemoteThread"), &["calls_process"]);
        assert_eq!(tags_for_import("BCryptDecrypt"), &["calls_crypto"]);
        assert_eq!(tags_for_import("LoadLibraryA"), &["calls_loader"]);
        assert_eq!(tags_for_import("IsDebuggerPresent"), &["calls_debug"]);
        assert!(tags_for_import("SomeRandomFunction").is_empty());
    }

    #[test]
    fn tags_dedup_across_imports() {
        let names = vec!["HeapAlloc", "VirtualAlloc", "memcpy", "memmove"];
        let tags = tags_for_imports(names);
        // alloc + memcpy, deduped, sorted alphabetically by BTreeSet.
        assert_eq!(tags, vec!["calls_alloc", "calls_memcpy"]);
    }
}
