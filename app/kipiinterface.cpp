// vim: set tabstop=4 shiftwidth=4 expandtab:
/*
Gwenview: an image viewer
Copyright 2000-2008 Aurélien Gâteau <agateau@kde.org>
Copyright 2008      Angelo Naselli  <anaselli@linux.it>

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
#include "kipiinterface.moc"

// Qt
#include <QList>
#include <QMenu>
#include <QRegExp>

// KDE
#include <KAction>
#include <KActionCollection>
#include <KDebug>
#include <KUrl>
#include <KXMLGUIFactory>
#include <KDirLister>

// KIPI
#include <libkipi/imagecollectionshared.h>
#include <libkipi/imageinfo.h>
#include <libkipi/imageinfoshared.h>
#include <libkipi/plugin.h>
#include <libkipi/pluginloader.h>

// local
#include "mainwindow.h"
#include "contextmanager.h"
#include "kipiimagecollectionselector.h"
#include "kipiuploadwidget.h"
#include <lib/jpegcontent.h>
#include <lib/mimetypeutils.h>
#include <lib/semanticinfo/sorteddirmodel.h>

namespace Gwenview
{
#undef ENABLE_LOG
#undef LOG

//#define ENABLE_LOG
#ifdef ENABLE_LOG
#define LOG(x) kDebug() << x
#else
#define LOG(x) ;
#endif

class KIPIImageInfo : public KIPI::ImageInfoShared
{
    static const QRegExp sExtensionRE;
public:
    KIPIImageInfo(KIPI::Interface* interface, const KUrl& url)
    : KIPI::ImageInfoShared(interface, url)
    {}

    QString title()
    {
        QString txt = _url.fileName();
        txt.replace('_', ' ');
        txt.remove(sExtensionRE);
        return txt;
    }

    QString description()
    {
        if (!_url.isLocalFile()) return QString();

        JpegContent content;
        bool ok = content.load(_url.toLocalFile());
        if (!ok) return QString();

        return content.comment();
    }

    void setDescription(const QString&)
    {}

    int angle()
    {
        loadMetaInfo();

        if (!mMetaInfo.isValid()) {
            return 0;
        }

        const KFileMetaInfoItem& mii = mMetaInfo.item("http://freedesktop.org/standards/xesam/1.0/core#orientation");
        bool ok = false;
        const Orientation orientation = (Orientation)mii.value().toInt(&ok);
        if (!ok) {
            return 0;
        }

        switch (orientation) {
        case NOT_AVAILABLE:
        case NORMAL:
            return 0;

        case ROT_90:
            return 90;

        case ROT_180:
            return 180;

        case ROT_270:
            return 270;

        case HFLIP:
        case VFLIP:
        case TRANSPOSE:
        case TRANSVERSE:
            kWarning() << "Can't represent an orientation value of" << orientation << "as an angle (" << _url << ')';
            return 0;
        }

        kWarning() << "Don't know how to handle an orientation value of" << orientation << '(' << _url << ')';
        return 0;
    }

    QMap<QString, QVariant> attributes() {
        return QMap<QString, QVariant>();
    }

    void delAttributes(const QStringList&)
    {}

    void clearAttributes()
    {}

    void addAttributes(const QMap<QString, QVariant>&)
    {}

private:
    KFileMetaInfo mMetaInfo;

    void loadMetaInfo()
    {
        if (!mMetaInfo.isValid()) {
            mMetaInfo = KFileMetaInfo(_url);
        }
    }
};

const QRegExp KIPIImageInfo::sExtensionRE("\\.[a-z0-9]+$", Qt::CaseInsensitive);

struct MenuInfo
{
    QString mName;
    QList<QAction*> mActions;

    MenuInfo()
    {}

    MenuInfo(const QString& name)
    : mName(name)
    {}
};
typedef QMap<KIPI::Category, MenuInfo> MenuInfoMap;

struct KIPIInterfacePrivate
{
    KIPIInterface* q;
    MainWindow* mMainWindow;
    QMenu* mPluginMenu;
    KIPI::PluginLoader* mPluginLoader;
    KIPI::PluginLoader::PluginList mPluginQueue;
    MenuInfoMap mMenuInfoMap;

    void setupPluginsMenu()
    {
        mPluginMenu = static_cast<QMenu*>(
                          mMainWindow->factory()->container("plugins", mMainWindow));
        QObject::connect(mPluginMenu, SIGNAL(aboutToShow()),
                         q, SLOT(loadPlugins()));
    }

    void createDummyPluginAction(const QString& text)
    {
        KAction* action = mMainWindow->actionCollection()->add<KAction>("dummy_plugin");
        action->setText(text);
        action->setShortcutConfigurable(false);
        action->setEnabled(false);
        mPluginMenu->addAction(action);
    }
};

KIPIInterface::KIPIInterface(MainWindow* mainWindow)
: KIPI::Interface(mainWindow)
, d(new KIPIInterfacePrivate)
{
    d->q = this;
    d->mMainWindow = mainWindow;
    d->mPluginLoader = 0;

    d->setupPluginsMenu();
    QObject::connect(d->mMainWindow->contextManager(), SIGNAL(selectionChanged()),
                     this, SLOT(slotSelectionChanged()));
    QObject::connect(d->mMainWindow->contextManager(), SIGNAL(currentDirUrlChanged()),
                     this, SLOT(slotDirectoryChanged()));
#if 0
//TODO instead of delaying can we load them all at start-up to use actions somewhere else?
// delay a bit, so that it's called after loadPlugins()
    QTimer::singleShot(0, this, SLOT(init()));
#endif
}

KIPIInterface::~KIPIInterface()
{
    delete d;
}

static bool actionLessThan(QAction* a1, QAction* a2)
{
    QString a1Text = a1->text().replace("&", "");
    QString a2Text = a2->text().replace("&", "");
    return QString::compare(a1Text, a2Text, Qt::CaseInsensitive) < 0;
}

void KIPIInterface::loadPlugins()
{
    // Already done
    if (d->mPluginLoader) {
        return;
    }

    d->mMenuInfoMap[KIPI::ImagesPlugin]      = MenuInfo(i18nc("@title:menu", "Images"));
    d->mMenuInfoMap[KIPI::EffectsPlugin]     = MenuInfo(i18nc("@title:menu", "Effects"));
    d->mMenuInfoMap[KIPI::ToolsPlugin]       = MenuInfo(i18nc("@title:menu", "Tools"));
    d->mMenuInfoMap[KIPI::ImportPlugin]      = MenuInfo(i18nc("@title:menu", "Import"));
    d->mMenuInfoMap[KIPI::ExportPlugin]      = MenuInfo(i18nc("@title:menu", "Export"));
    d->mMenuInfoMap[KIPI::BatchPlugin]       = MenuInfo(i18nc("@title:menu", "Batch Processing"));
    d->mMenuInfoMap[KIPI::CollectionsPlugin] = MenuInfo(i18nc("@title:menu", "Collections"));

    d->mPluginLoader = new KIPI::PluginLoader(QStringList(), this);
    d->mPluginQueue = d->mPluginLoader->pluginList();
    d->createDummyPluginAction(i18n("Loading..."));
    loadOnePlugin();
}

void KIPIInterface::loadOnePlugin()
{
    while (!d->mPluginQueue.isEmpty()) {
        KIPI::PluginLoader::Info* pluginInfo = d->mPluginQueue.takeFirst();
        if (!pluginInfo->shouldLoad()) {
            continue;
        }

        KIPI::Plugin* plugin = pluginInfo->plugin();
        if (!plugin) {
            kWarning() << "Plugin from library" << pluginInfo->library() << "failed to load";
            continue;
        }

        plugin->setup(d->mMainWindow);
        QList<KAction*> actions = plugin->actions();
        Q_FOREACH(KAction * action, actions) {
            KIPI::Category category = plugin->category(action);

            if (!d->mMenuInfoMap.contains(category)) {
                kWarning() << "Unknown category '" << category;
                continue;
            }

            d->mMenuInfoMap[category].mActions << action;
        }
        // FIXME: Port
        //plugin->actionCollection()->readShortcutSettings();

        // If we reach this point, we just loaded one plugin. Go back to the
        // event loop. We will come back to load the remaining plugins or create
        // the menu later
        QMetaObject::invokeMethod(this, "loadOnePlugin", Qt::QueuedConnection);
        return;
    }

    // If we reach this point, all plugins have been loaded. We can fill the
    // menu
    bool atLeastOnePluginLoaded = false;
    MenuInfoMap::Iterator
    it = d->mMenuInfoMap.begin(),
    end = d->mMenuInfoMap.end();
    for (; it != end; ++it) {
        MenuInfo& info = it.value();
        if (!info.mActions.isEmpty()) {
            QMenu* menu = d->mPluginMenu->addMenu(info.mName);
            qSort(info.mActions.begin(), info.mActions.end(), actionLessThan);
            Q_FOREACH(QAction * action, info.mActions) {
                atLeastOnePluginLoaded = true;
                menu->addAction(action);
            }
        }
    }

    delete d->mMainWindow->actionCollection()->action("dummy_plugin");
    if (!atLeastOnePluginLoaded) {
        d->createDummyPluginAction(i18n("No Plugin Found"));
    }
}

QList<QAction*> KIPIInterface::pluginActions(KIPI::Category category) const
{
    const_cast<KIPIInterface*>(this)->loadPlugins();
    return d->mMenuInfoMap.value(category).mActions;
}

void KIPIInterface::init()
{
    slotDirectoryChanged();
    slotSelectionChanged();
}

KIPI::ImageCollection KIPIInterface::currentAlbum()
{
    LOG("");
    const ContextManager* contextManager = d->mMainWindow->contextManager();
    const KUrl url = contextManager->currentDirUrl();
    const SortedDirModel* model = contextManager->dirModel();

    KUrl::List list;
    const int count = model->rowCount();
    for (int row = 0; row < count; ++row) {
        const QModelIndex& index = model->index(row, 0);
        const KFileItem item = model->itemForIndex(index);
        if (MimeTypeUtils::fileItemKind(item) == MimeTypeUtils::KIND_RASTER_IMAGE) {
            list << item.targetUrl();
        }
    }

    return KIPI::ImageCollection(new ImageCollection(url, url.fileName(), list));
}

KIPI::ImageCollection KIPIInterface::currentSelection()
{
    LOG("");

    KFileItemList fileList = d->mMainWindow->contextManager()->selectedFileItemList();
    KUrl::List list = fileList.urlList();
    KUrl url = d->mMainWindow->contextManager()->currentUrl();

    return KIPI::ImageCollection(new ImageCollection(url, url.fileName(), list));
}

QList<KIPI::ImageCollection> KIPIInterface::allAlbums()
{
    LOG("");
    QList<KIPI::ImageCollection> list;
    list << currentAlbum() << currentSelection();
    return list;
}

KIPI::ImageInfo KIPIInterface::info(const KUrl& url)
{
    LOG("");
    return KIPI::ImageInfo(new KIPIImageInfo(this, url));
}

int KIPIInterface::features() const
{
    return KIPI::HostAcceptNewImages;
}

/**
 * KDirLister will pick up the image if necessary, so no updating is needed
 * here, it is however necessary to discard caches if the plugin preserves timestamp
 */
bool KIPIInterface::addImage(const KUrl&, QString&)
{
//TODO  setContext(const KUrl& currentUrl, const KFileItemList& selection)?
    //Cache::instance()->invalidate( url );
    return true;
}

void KIPIInterface::delImage(const KUrl&)
{
//TODO
}

void KIPIInterface::refreshImages(const KUrl::List&)
{
// TODO
}

KIPI::ImageCollectionSelector* KIPIInterface::imageCollectionSelector(QWidget *parent)
{
    return new KIPIImageCollectionSelector(this, parent);
}

KIPI::UploadWidget* KIPIInterface::uploadWidget(QWidget *parent)
{
    return (new KIPIUploadWidget(this, parent));
}

void KIPIInterface::slotSelectionChanged()
{
    emit selectionChanged(!d->mMainWindow->contextManager()->selectedFileItemList().isEmpty());
}

void KIPIInterface::slotDirectoryChanged()
{
    emit currentAlbumChanged(true);
}

} //namespace
