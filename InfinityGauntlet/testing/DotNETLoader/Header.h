#pragma once
#include <windows.h>
#include <mscoree.h>
#include <oleauto.h>
#include <vector>
#include <string>
#include <metahost.h>
#include <atlbase.h>
#include <stdexcept>
#pragma comment(lib, "mscoree.lib")
#import "mscorlib.tlb" raw_interfaces_only \
    high_property_prefixes("_get","_put","_putref") \
    rename("ReportEvent", "InteropServices_ReportEvent") \
    rename("or", "objRefOr")
using namespace mscorlib;