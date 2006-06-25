// vim: set tabstop=4 shiftwidth=4 noexpandtab
/* This file is based on kfiledetailview.cpp from the KDE libs. Original
   copyright follows.
*/
/* This file is part of the KDE libraries
   Copyright (C) 1997 Stephan Kulow <coolo@kde.org>
                 2000, 2001 Carsten Pfeiffer <pfeiffer@kde.org>

   This library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Library General Public
   License as published by the Free Software Foundation; either
   version 2 of the License, or (at your option) any later version.

   This library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Library General Public License for more details.

   You should have received a copy of the GNU Library General Public License
   along with this library; see the file COPYING.LIB.	If not, write to
   the Free Software Foundation, Inc., 59 Temple Place - Suite 330,
   Boston, MA 02111-1307, USA.
*/

// KDE includes
#include <kglobal.h>
#include <klocale.h>

// Our includes
#include "filedetailviewitem.h"
#include "filedetailview.h"
#include "timeutils.h"
namespace Gwenview {


void FileDetailViewItem::init()
{
	time_t time = TimeUtils::getTime(inf);
	setPixmap( COL_NAME, inf->pixmap(KIcon::SizeSmall));

	setText( COL_NAME, inf->text() );
	setText( COL_SIZE, KGlobal::locale()->formatNumber( inf->size(), 0));
	setText( COL_DATE, TimeUtils::formatTime(time) );
	setText( COL_PERM,	inf->permissionsString() );
	setText( COL_OWNER, inf->user() );
	setText( COL_GROUP, inf->group() );
}


const QPixmap* FileDetailViewItem::pixmap(int column) const {
	const QPixmap* normalPix = KListViewItem::pixmap(column);
	if (column!=0) {
		return normalPix;
	}

	FileDetailView* view=static_cast<FileDetailView*>(listView());
	FileDetailViewItem* viewedItem=view->viewItem(view->shownFileItem());
	if (viewedItem!=this) {
		return normalPix;
	}

	if (isSelected()) {
		return &view->mShownItemSelectedPixmap;
	} else {
		return &view->mShownItemUnselectedPixmap;
	}
}


} // namespace
