// vim: set tabstop=4 shiftwidth=4 noexpandtab
/*
Gwenview - A simple image viewer for KDE
Copyright 2000-2004 Aur�lien G�teau
 
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
Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 
*/
#ifndef GVDOCUMENTIMPL_H
#define GVDOCUMENTIMPL_H

// Qt
#include <qobject.h>
#include <qrect.h>

// Local
#include "gvdocument.h"
#include "gvimageutils.h"


class GVDocumentImpl : public QObject {
Q_OBJECT
public:
	GVDocumentImpl(GVDocument* document);
	virtual ~GVDocumentImpl();
	
	void switchToImpl(GVDocumentImpl*);
	void setImage(QImage);
	void setImageFormat(const char*);
	void setFileSize(int) const;
	
	virtual QString comment() const;
	virtual GVDocument::CommentState commentState() const;
	virtual void setComment(const QString&);
	
	virtual void suspendLoading();
	virtual void resumeLoading();

	virtual void modify(GVImageUtils::Orientation);
	virtual bool save(const KURL&, const char* format) const;

signals:
	void finished(bool success);
	void sizeUpdated(int width, int height);
	void rectUpdated(const QRect&);
	
protected:
	GVDocument* mDocument;
};

class GVDocumentEmptyImpl : public GVDocumentImpl {
public:
	GVDocumentEmptyImpl(GVDocument* document)
	: GVDocumentImpl(document) {
		setImage(QImage());
		setImageFormat(0);
	}
};

#endif /* GVDOCUMENTIMPL_H */
