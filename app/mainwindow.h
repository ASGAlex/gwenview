/*
Gwenview: an image viewer
Copyright 2007 Aur�lien G�teau

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
Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.

*/
#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QAction>

#include <KMainWindow>

#include <memory>

class QModelIndex;

class KUrl;

namespace Gwenview {

class MainWindow : public KMainWindow {
Q_OBJECT
public:
	MainWindow();
	   
private Q_SLOTS:
	void setActiveViewModeAction(QAction* action);
	void openUrl(const KUrl&);
	void openUrlFromIndex(const QModelIndex&);
	void openUrlFromString(const QString& str);
	void goUp();

	void initDirModel();

private:
	class Private;
	std::auto_ptr<Private> d;
};

} // namespace

#endif /* MAINWINDOW_H */
