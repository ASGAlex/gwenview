// vim: set tabstop=4 shiftwidth=4 expandtab:
/*
Gwenview: an image viewer
Copyright 2009 Aurélien Gâteau <agateau@kde.org>

This program is free software; you can redistribute it and/or
modify it under the terms of the GNU General Public License
as published by the Free Software Foundation; either version 2
of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program; if not, write to the Free Software
Foundation, Inc., 51 Franklin Street, Fifth Floor, Cambridge, MA 02110-1301, USA.

*/
// Self
#include "fileutils.h"

// Qt
#include <QFile>
#include <QFileInfo>
#include <QUrl>

// KDE
#include <QDebug>
#include <KFileItem>
#include <KIO/CopyJob>
#include <KIO/Job>
#include <kio/jobclasses.h>
#include <KIO/JobUiDelegate>
#include <KJobWidgets>

// libc
#include <errno.h>
#include <stdlib.h>
#include <string.h>

#if defined(_WIN32)
#include <time.h>
#include <math.h>
#include <errno.h>
#include <sys/stat.h>
#include <string.h>
#include <windows.h>
#include <accctrl.h>
#include <aclapi.h>

static PSECURITY_DESCRIPTOR
create_sd (int permissions)
{
  PSECURITY_DESCRIPTOR pSD = NULL;
  int i;
  int j;
  EXPLICIT_ACCESS ea[3];
  PSID sids[3] = { NULL, NULL, NULL };
  WELL_KNOWN_SID_TYPE sidtypes[3] = { WinCreatorOwnerSid, WinCreatorGroupSid, WinWorldSid };
  int ea_len = 0;
  DWORD dwRes, dwDisposition;
 PACL pACL = NULL;

  /* Initialize a security descriptor. */
  pSD = (PSECURITY_DESCRIPTOR) LocalAlloc (LPTR, SECURITY_DESCRIPTOR_MIN_LENGTH); 
  if (NULL == pSD) 
  { 
    errno = ENOMEM;
    return NULL;
  }

  if (!InitializeSecurityDescriptor (pSD, SECURITY_DESCRIPTOR_REVISION))
  {  
    LocalFree (pSD);
    errno = EIO;
    return NULL;
  }

  for (i = 0; i < 3; i++)
  {
    BOOL b;
    DWORD bytes;
    int imasked = permissions & (07 << (2 - i));
    if (!imasked)
      continue;

    bytes = SECURITY_MAX_SID_SIZE;
    sids[ea_len] = (PSID) LocalAlloc (LMEM_FIXED, bytes);
    if (NULL == sids[ea_len])
    { 
      errno = ENOMEM;
      LocalFree (pSD);
      for (j = 0; j < ea_len; j++)
      {
        if (sids[j] != NULL)
        {
          LocalFree (sids[j]);
          sids[j] = NULL;
        }
      }
      return NULL;
    }

    b = CreateWellKnownSid (sidtypes[i], NULL, sids[ea_len], &bytes);
    if (!b)
    {
      errno = EINVAL;
      LocalFree (pSD);
      for (j = 0; j < ea_len; j++)
      {
        if (sids[j] != NULL)
        {
          LocalFree (sids[j]);
          sids[j] = NULL;
        }
      }
      return NULL;
   }

    /* Initialize an EXPLICIT_ACCESS structure for an ACE. */
    ZeroMemory (&ea[ea_len], sizeof(EXPLICIT_ACCESS));
    bytes = 0;
    if (01 & imasked)
      bytes = bytes | GENERIC_READ;
    if (02 & imasked)
      bytes = bytes | GENERIC_WRITE;
    if (04 & imasked)
      bytes = bytes | GENERIC_EXECUTE;
    ea[ea_len].grfAccessPermissions = bytes;
    ea[ea_len].grfAccessMode = SET_ACCESS;
   ea[ea_len].grfInheritance= NO_INHERITANCE;
    ea[ea_len].Trustee.TrusteeForm = TRUSTEE_IS_SID;
   ea[ea_len].Trustee.TrusteeType = TRUSTEE_IS_WELL_KNOWN_GROUP;
    ea[ea_len].Trustee.ptstrName  = (LPTSTR) sids[ea_len];
    ea_len = ea_len + 1;
  }

  /* Create a new ACL that contains the new ACEs. */
  dwRes = SetEntriesInAcl (ea_len, ea, NULL, &pACL);
  if (ERROR_SUCCESS != dwRes) 
  {
    errno = EIO;
    LocalFree (pSD);
   for (j = 0; j < ea_len; j++)
    {
      if (sids[j] != NULL)
      {
        LocalFree (sids[j]);
        sids[j] = NULL;
     }
    }
    return NULL;
  }

  for (j = 0; j < ea_len; j++)
 {
    if (sids[j] != NULL)
    {
      LocalFree (sids[j]);
      sids[j] = NULL;
   }
  }

  /* Add the ACL to the security descriptor. */
  if (!SetSecurityDescriptorDacl (pSD,
         TRUE,     // bDaclPresent flag
          pACL,
          FALSE))   // not a default DACL
  {
    errno = EIO;
   LocalFree (pSD);
    LocalFree (pACL);
    return NULL;
  } 

 return pSD;
}

static void
free_sd (PSECURITY_DESCRIPTOR sd)
{
  BOOL b, present, defaulted;
  PACL pACL = NULL;
  present = FALSE;
  b = GetSecurityDescriptorDacl (sd, &present, &pACL, &defaulted);
  if (b && present && !defaulted && pACL)
    LocalFree (pACL);
  LocalFree (sd);
}

static void
rand_template (char *_template, size_t l)
{
  int i;
  for (i = l - 6; i < l; i++)
  {
    int r = rand ();
    if ((r / (RAND_MAX + 1)) > ((RAND_MAX + 1) / 2))
      _template[i] = 'A' + (double) rand () / (RAND_MAX + 1) * ('Z' - 'A');
    else
      _template[i] = 'a' + (double) rand () / (RAND_MAX + 1) * ('z' - 'a');
  }
}

static char *
mkdtemp (char *_template)
{
  int i;
  size_t l;
  BOOL b;
  SECURITY_ATTRIBUTES sa;
  
  if (_template == NULL)
  {
    errno = EINVAL;
    return NULL;
 }
  l = strlen (_template);
  if (l < 6 || strcmp (&_template[l - 6], "XXXXXX") != 0)
  {
    errno = EINVAL;
    return NULL;
  }
  srand(time (NULL));
  sa.nLength = sizeof (sa);
  sa.lpSecurityDescriptor = create_sd (0700);
  sa.bInheritHandle = FALSE;
  do
  {
    rand_template (_template, l);
    SetLastError (0);
    b = CreateDirectoryA (_template, &sa);
  } while (!b && GetLastError () == ERROR_ALREADY_EXISTS);
  free_sd (sa.lpSecurityDescriptor);
  if (!b)
  {
    errno = EIO;
    return NULL;
  }
  else
  {
    errno = 0;
    return _template;
  }
}
#endif


namespace Gwenview
{
namespace FileUtils
{

bool contentsAreIdentical(const QUrl& url1, const QUrl& url2, QWidget* authWindow)
{
    // FIXME: Support remote urls
    KIO::StatJob *statJob = KIO::mostLocalUrl(url1);
    KJobWidgets::setWindow(statJob, authWindow);
    if (!statJob->exec()) {
        qWarning() << "Unable to stat" << url1;
        return false;
    }
    QFile file1(statJob->mostLocalUrl().toLocalFile());
    if (!file1.open(QIODevice::ReadOnly)) {
        // Can't read url1, assume it's different from url2
        qWarning() << "Can't read" << url1;
        return false;
    }

    statJob = KIO::mostLocalUrl(url2);
    KJobWidgets::setWindow(statJob, authWindow);
    if (!statJob->exec()) {
        qWarning() << "Unable to stat" << url2;
        return false;
    }

    QFile file2(statJob->mostLocalUrl().toLocalFile());
    if (!file2.open(QIODevice::ReadOnly)) {
        // Can't read url2, assume it's different from url1
        qWarning() << "Can't read" << url2;
        return false;
    }

    const int CHUNK_SIZE = 4096;
    while (!file1.atEnd() && !file2.atEnd()) {
        QByteArray url1Array = file1.read(CHUNK_SIZE);
        QByteArray url2Array = file2.read(CHUNK_SIZE);

        if (url1Array != url2Array) {
            return false;
        }
    }
    if (file1.atEnd() && file2.atEnd()) {
        return true;
    } else {
        qWarning() << "One file ended before the other";
        return false;
    }
}

RenameResult rename(const QUrl& src, const QUrl& dst_, QWidget* authWindow)
{
    QUrl dst = dst_;
    RenameResult result = RenamedOK;
    int count = 1;

    QFileInfo fileInfo(dst.fileName());
    QString prefix = fileInfo.completeBaseName() + '_';
    QString suffix = '.' + fileInfo.suffix();

    // Get src size
    KIO::StatJob *sourceStat = KIO::stat(src);
    KJobWidgets::setWindow(sourceStat, authWindow);
    if (!sourceStat->exec()) {
        return RenameFailed;
    }
    KFileItem item(sourceStat->statResult(), src, true /* delayedMimeTypes */);
    KIO::filesize_t srcSize = item.size();

    // Find unique name
    KIO::StatJob *statJob = KIO::stat(dst);
    KJobWidgets::setWindow(statJob, authWindow);
    while (statJob->exec()) {
        // File exists. If it's not the same, try to create a new name
        item = KFileItem(statJob->statResult(), dst, true /* delayedMimeTypes */);
        KIO::filesize_t dstSize = item.size();

        if (srcSize == dstSize && contentsAreIdentical(src, dst, authWindow)) {
            // Already imported, skip it
            KIO::Job* job = KIO::file_delete(src, KIO::HideProgressInfo);
            KJobWidgets::setWindow(job, authWindow);

            return Skipped;
        }
        result = RenamedUnderNewName;

        dst.setPath(dst.adjusted(QUrl::RemoveFilename).path() + prefix + QString::number(count) + suffix);
        statJob = KIO::stat(dst);
        KJobWidgets::setWindow(statJob, authWindow);

        ++count;
    }

    // Rename
    KIO::Job* job = KIO::rename(src, dst, KIO::HideProgressInfo);
    KJobWidgets::setWindow(job, authWindow);
    if (!job->exec()) {
        result = RenameFailed;
    }
    return result;
}

QString createTempDir(const QString& baseDir, const QString& prefix, QString* errorMessage)
{
    Q_ASSERT(errorMessage);

    QByteArray name = QFile::encodeName(baseDir + '/' + prefix + "XXXXXX");

    if (!mkdtemp(name.data())) {
        // Failure
        *errorMessage = QString::fromLocal8Bit(::strerror(errno));
        return QString();
    }
    return QFile::decodeName(name + '/');
}

} // namespace
} // namespace
