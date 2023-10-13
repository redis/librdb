/*
 * The core library of LIBRDB is librdb.so. It is also responsible for linking
 * and combining Redis object files from this folder. The extension library of
 * LIBRDB (librdb-ext.so) also requires certain functionality from this folder,
 * such as the use of the rax data structure or CRC.
 *
 * Instead of refactoring and creating an additional shared library, or making
 * copies for each library (with all the associated implications) we shall expose
 * specific symbols from librdb.so that are needed by librdb-ext.so. These symbols
 * won't be documented in the API, but they will be available for use. Since we
 * compile by default with hidden visibility, we need to mark them explicitly as
 * visible using the following macro.
 *
 * While it might initially seem cumbersome to manually designate each function as
 * visible, this approach has its benefits. By carefully selecting the functions
 * to expose, we are encouraged to contemplate what we are exposing and why.
 * Moreover, it helps prevent the cluttering clients of librdb with unnecessary
 * symbols.
 *
 */

#ifndef __HIDDEN_API_H__
#define __HIDDEN_API_H__

#define _LIBRDB_HIDDEN_API __attribute__((visibility("default")))

#endif /*__HIDDEN_API_H__*/
