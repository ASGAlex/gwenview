// vim: set tabstop=4 shiftwidth=4 expandtab:
/*
Gwenview: an image viewer
Copyright 2008 Aurélien Gâteau <agateau@kde.org>
Copyright 2014 Vishesh Handa <me@vhanda.in>

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
#ifndef BALOOSEMANTICINFOBACKEND_H
#define BALOOSEMANTICINFOBACKEND_H

#include <lib/gwenviewlib_export.h>

// Qt

// KDE

// Local
#include "abstractsemanticinfobackend.h"


namespace Gwenview
{

/**
 * A real metadata backend using Baloo to store and retrieve metadata.
 */
class GWENVIEWLIB_EXPORT BalooSemanticInfoBackend : public AbstractSemanticInfoBackEnd
{
    Q_OBJECT
public:
    explicit BalooSemanticInfoBackend(QObject* parent);
    ~BalooSemanticInfoBackend() Q_DECL_OVERRIDE;

    TagSet allTags() const Q_DECL_OVERRIDE;

    void refreshAllTags() Q_DECL_OVERRIDE;

    void storeSemanticInfo(const QUrl&, const SemanticInfo&) Q_DECL_OVERRIDE;

    void retrieveSemanticInfo(const QUrl&) Q_DECL_OVERRIDE;

    QString labelForTag(const SemanticInfoTag&) const Q_DECL_OVERRIDE;

    SemanticInfoTag tagForLabel(const QString&) Q_DECL_OVERRIDE;

private:
    struct Private;
    Private* const d;
};

} // namespace

#endif /* BALOOSEMANTICINFOBACKEND_H */
