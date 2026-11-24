/* Umbrella header for RelayPKCS11.xcframework: the five platform macros pkcs11.h asks its
 * includer to define, set the usual way for Apple platforms (no structure packing, as on
 * every UNIX), then the unmodified OASIS headers. The library exports one symbol,
 * C_GetFunctionList; call everything else through the returned CK_FUNCTION_LIST. */
#ifndef RELAY_PKCS11_H
#define RELAY_PKCS11_H

#define CK_PTR *
#define CK_DECLARE_FUNCTION(returnType, name) returnType name
#define CK_DECLARE_FUNCTION_POINTER(returnType, name) returnType (* name)
#define CK_CALLBACK_FUNCTION(returnType, name) returnType (* name)
#ifndef NULL_PTR
#define NULL_PTR 0
#endif

#include "pkcs11.h"

#endif
