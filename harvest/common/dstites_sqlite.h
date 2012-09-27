//
//  dstites_sqlite.h
//  harvest
//
//  Created by David R. Stites on 9/26/12.
//
//

#ifndef harvest_dstites_sqlite_h
#define harvest_dstites_sqlite_h

#define CALL_SQLITE(f)                                          \
{                                                           \
int i;                                                  \
i = sqlite3_ ## f;                                      \
if (i != SQLITE_OK) {                                   \
fprintf (stderr, "%s failed with status %d: %s\n",  \
#f, i, sqlite3_errmsg (db_handle));               \
exit (1);                                           \
}                                                       \
}                                                           \

#define CALL_SQLITE_EXPECT(f,x)                                 \
{                                                           \
int i;                                                  \
i = sqlite3_ ## f;                                      \
if (i != SQLITE_ ## x) {                                \
fprintf (stderr, "%s failed with status %d: %s\n",  \
#f, i, sqlite3_errmsg (db_handle));               \
exit (1);                                           \
}                                                       \
}

#endif
