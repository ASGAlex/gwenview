// vim: set tabstop=4 shiftwidth=4 expandtab:
/*
Gwenview: an image viewer
Copyright 2008 Aurélien Gâteau <agateau@kde.org>

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
#include "documentview.h"

// C++ Standard library
#include <cmath>

// Qt
#include <QApplication>
#include <QGraphicsLinearLayout>
#include <QGraphicsProxyWidget>
#include <QGraphicsScene>
#include <QGraphicsSceneMouseEvent>
#include <QGraphicsSceneWheelEvent>
#include <QGraphicsOpacityEffect>
#include <QGraphicsView>
#include <QPainter>
#include <QPropertyAnimation>
#include <QPointer>
#include <QDebug>
#include <QIcon>
#include <QUrl>
#include <QDrag>
#include <QMimeData>
#include <QStyleHints>

// KDE
#include <KLocalizedString>
#include <KFileItem>
#include <KUrlMimeData>

// Local
#include <lib/document/document.h>
#include <lib/document/documentfactory.h>
#include <lib/documentview/abstractrasterimageviewtool.h>
#include <lib/documentview/birdeyeview.h>
#include <lib/documentview/loadingindicator.h>
#include <lib/documentview/messageviewadapter.h>
#include <lib/documentview/rasterimageview.h>
#include <lib/documentview/rasterimageviewadapter.h>
#include <lib/documentview/svgviewadapter.h>
#include <lib/documentview/videoviewadapter.h>
#include <lib/hud/hudbutton.h>
#include <lib/hud/hudwidget.h>
#include <lib/graphicswidgetfloater.h>
#include <lib/gvdebug.h>
#include <lib/gwenviewconfig.h>
#include <lib/mimetypeutils.h>
#include <lib/signalblocker.h>
#include <lib/urlutils.h>
#include <lib/thumbnailview/dragpixmapgenerator.h>
#include <lib/thumbnailprovider/thumbnailprovider.h>

namespace Gwenview
{

#undef ENABLE_LOG
#undef LOG
//#define ENABLE_LOG
#ifdef ENABLE_LOG
#define LOG(x) //qDebug() << x
#else
#define LOG(x) ;
#endif

static const qreal REAL_DELTA = 0.001;
static const qreal MAXIMUM_ZOOM_VALUE = qreal(DocumentView::MaximumZoom);
static const auto MINSTEP = sqrt(0.5);
static const auto MAXSTEP = sqrt(2.0);

static const int COMPARE_MARGIN = 4;

const int DocumentView::MaximumZoom = 16;
const int DocumentView::AnimDuration = 250;

struct DocumentViewPrivate
{
    DocumentView* q;
    int mSortKey; // Used to sort views when displayed in compare mode
    HudWidget* mHud;
    BirdEyeView* mBirdEyeView;
    QPointer<QPropertyAnimation> mMoveAnimation;
    QPointer<QPropertyAnimation> mFadeAnimation;
    QGraphicsOpacityEffect* mOpacityEffect;

    LoadingIndicator* mLoadingIndicator;

    QScopedPointer<AbstractDocumentViewAdapter> mAdapter;
    QList<qreal> mZoomSnapValues;
    Document::Ptr mDocument;
    DocumentView::Setup mSetup;
    bool mCurrent;
    bool mCompareMode;
    int controlWheelAccumulatedDelta;

    QPointF mDragStartPosition;
    QPointer<ThumbnailProvider> mDragThumbnailProvider;
    QPointer<QDrag> mDrag;

    void setCurrentAdapter(AbstractDocumentViewAdapter* adapter)
    {
        Q_ASSERT(adapter);
        mAdapter.reset(adapter);

        adapter->widget()->setParentItem(q);
        resizeAdapterWidget();

        if (adapter->canZoom()) {
            QObject::connect(adapter, SIGNAL(zoomChanged(qreal)),
                             q, SLOT(slotZoomChanged(qreal)));
            QObject::connect(adapter, SIGNAL(zoomInRequested(QPointF)),
                             q, SLOT(zoomIn(QPointF)));
            QObject::connect(adapter, SIGNAL(zoomOutRequested(QPointF)),
                             q, SLOT(zoomOut(QPointF)));
            QObject::connect(adapter, SIGNAL(zoomToFitChanged(bool)),
                             q, SIGNAL(zoomToFitChanged(bool)));
            QObject::connect(adapter, SIGNAL(zoomToFillChanged(bool)),
                             q, SIGNAL(zoomToFillChanged(bool)));
        }
        QObject::connect(adapter, SIGNAL(scrollPosChanged()),
                         q, SIGNAL(positionChanged()));
        QObject::connect(adapter, SIGNAL(previousImageRequested()),
                         q, SIGNAL(previousImageRequested()));
        QObject::connect(adapter, SIGNAL(nextImageRequested()),
                         q, SIGNAL(nextImageRequested()));
        QObject::connect(adapter, SIGNAL(toggleFullScreenRequested()),
                         q, SIGNAL(toggleFullScreenRequested()));
        QObject::connect(adapter, SIGNAL(completed()),
                         q, SLOT(slotCompleted()));

        adapter->loadConfig();

        adapter->widget()->installSceneEventFilter(q);
        if (mCurrent) {
            adapter->widget()->setFocus();
        }

        if (mSetup.valid && adapter->canZoom()) {
            adapter->setZoomToFit(mSetup.zoomToFit);
            adapter->setZoomToFill(mSetup.zoomToFill);
            if (!mSetup.zoomToFit && !mSetup.zoomToFill) {
                adapter->setZoom(mSetup.zoom);
                adapter->setScrollPos(mSetup.position);
            }
        }
        q->adapterChanged();
        q->positionChanged();
        if (adapter->canZoom()) {
            if (adapter->zoomToFit()) {
                q->zoomToFitChanged(true);
            } else if (adapter->zoomToFill()) {
                q->zoomToFillChanged(true);
            } else {
                q->zoomChanged(adapter->zoom());
            }
        }
        if (adapter->rasterImageView()) {
            QObject::connect(adapter->rasterImageView(), SIGNAL(currentToolChanged(AbstractRasterImageViewTool*)),
                             q, SIGNAL(currentToolChanged(AbstractRasterImageViewTool*)));
        }
    }

    void setupLoadingIndicator()
    {
        mLoadingIndicator = new LoadingIndicator(q);
        GraphicsWidgetFloater* floater = new GraphicsWidgetFloater(q);
        floater->setChildWidget(mLoadingIndicator);
    }

    HudButton* createHudButton(const QString& text, const char* iconName, bool showText)
    {
        HudButton* button = new HudButton;
        if (showText) {
            button->setText(text);
        } else {
            button->setToolTip(text);
        }
        button->setIcon(QIcon::fromTheme(iconName));
        return button;
    }

    void setupHud()
    {
        HudButton* trashButton = createHudButton(i18nc("@info:tooltip", "Trash"), "user-trash", false);
        HudButton* deselectButton = createHudButton(i18nc("@action:button", "Deselect"), "list-remove", true);

        QGraphicsWidget* content = new QGraphicsWidget;
        QGraphicsLinearLayout* layout = new QGraphicsLinearLayout(content);
        layout->addItem(trashButton);
        layout->addItem(deselectButton);

        mHud = new HudWidget(q);
        mHud->init(content, HudWidget::OptionNone);
        GraphicsWidgetFloater* floater = new GraphicsWidgetFloater(q);
        floater->setChildWidget(mHud);
        floater->setAlignment(Qt::AlignBottom | Qt::AlignHCenter);

        QObject::connect(trashButton, SIGNAL(clicked()), q, SLOT(emitHudTrashClicked()));
        QObject::connect(deselectButton, SIGNAL(clicked()), q, SLOT(emitHudDeselectClicked()));

        mHud->hide();
    }

    void setupBirdEyeView()
    {
        if (mBirdEyeView) {
            delete mBirdEyeView;
        }
        mBirdEyeView = new BirdEyeView(q);
        mBirdEyeView->setZValue(1);
    }

    void updateCaption()
    {
        if (!mCurrent) {
            return;
        }
        QString caption;

        Document::Ptr doc = mAdapter->document();
        if (!doc) {
            emit q->captionUpdateRequested(caption);
            return;
        }

        caption = doc->url().fileName();
        QSize size = doc->size();
        if (size.isValid()) {
            caption +=
                QString(" - %1x%2")
                .arg(size.width())
                .arg(size.height());
            if (mAdapter->canZoom()) {
                int intZoom = qRound(mAdapter->zoom() * 100);
                caption += QString(" - %1%")
                           .arg(intZoom);
            }
        }
        emit q->captionUpdateRequested(caption);
    }

    void uncheckZoomToFit()
    {
        if (mAdapter->zoomToFit()) {
            mAdapter->setZoomToFit(false);
        }
    }

    void uncheckZoomToFill()
    {
        if (mAdapter->zoomToFill()) {
            mAdapter->setZoomToFill(false);
        }
    }

    void setZoom(qreal zoom, const QPointF& center = QPointF(-1, -1))
    {
        uncheckZoomToFit();
        uncheckZoomToFill();
        zoom = qBound(q->minimumZoom(), zoom, MAXIMUM_ZOOM_VALUE);
        mAdapter->setZoom(zoom, center);
    }

    void updateZoomSnapValues()
    {
        qreal min = q->minimumZoom();

        mZoomSnapValues.clear();
        for (qreal zoom = MINSTEP; zoom > min; zoom *= MINSTEP) {
            mZoomSnapValues << zoom;
        }
        mZoomSnapValues << min;

        std::reverse(mZoomSnapValues.begin(), mZoomSnapValues.end());

        for (qreal zoom = 1; zoom < MAXIMUM_ZOOM_VALUE; zoom *= MAXSTEP) {
            mZoomSnapValues << zoom;
        }
        mZoomSnapValues << MAXIMUM_ZOOM_VALUE;

        q->minimumZoomChanged(min);
    }

    void showLoadingIndicator()
    {
        if (!mLoadingIndicator) {
            setupLoadingIndicator();
        }
        mLoadingIndicator->show();
        mLoadingIndicator->setZValue(1);
    }

    void hideLoadingIndicator()
    {
        if (!mLoadingIndicator) {
            return;
        }
        mLoadingIndicator->hide();
    }

    void resizeAdapterWidget()
    {
        QRectF rect = QRectF(QPointF(0, 0), q->boundingRect().size());
        if (mCompareMode) {
            rect.adjust(COMPARE_MARGIN, COMPARE_MARGIN, -COMPARE_MARGIN, -COMPARE_MARGIN);
        }
        mAdapter->widget()->setGeometry(rect);
    }

    void fadeTo(qreal value)
    {
        if (mFadeAnimation.data()) {
            qreal endValue = mFadeAnimation.data()->endValue().toReal();
            if (qFuzzyCompare(value, endValue)) {
                // Same end value, don't change the actual animation
                return;
            }
        }
        // Create a new fade animation
        QPropertyAnimation* anim = new QPropertyAnimation(mOpacityEffect, "opacity");
        anim->setStartValue(mOpacityEffect->opacity());
        anim->setEndValue(value);
        if (qFuzzyCompare(value, 1)) {
            QObject::connect(anim, SIGNAL(finished()),
                            q, SLOT(slotFadeInFinished()));
        }
        QObject::connect(anim, SIGNAL(finished()), q, SIGNAL(isAnimatedChanged()));
        anim->setDuration(DocumentView::AnimDuration);
        mFadeAnimation = anim;
        q->isAnimatedChanged();
        anim->start(QAbstractAnimation::DeleteWhenStopped);
    }

    bool canPan() const
    {
        if (!q->canZoom()) {
            return false;
        }

        const QSize zoomedImageSize = mDocument->size() * q->zoom();
        const QSize viewPortSize = q->boundingRect().size().toSize();
        const bool imageWiderThanViewport = zoomedImageSize.width() > viewPortSize.width();
        const bool imageTallerThanViewport = zoomedImageSize.height() > viewPortSize.height();
        return (imageWiderThanViewport || imageTallerThanViewport);
    }

    void setDragPixmap(const QPixmap& pix)
    {
        if (mDrag) {
            DragPixmapGenerator::DragPixmap dragPixmap = DragPixmapGenerator::generate({pix}, 1);
            mDrag->setPixmap(dragPixmap.pix);
            mDrag->setHotSpot(dragPixmap.hotSpot);
        }
    }

    void executeDrag()
    {
        if (mDrag) {
            if (mAdapter->imageView()) {
                mAdapter->imageView()->resetDragCursor();
            }
            mDrag->exec(Qt::MoveAction | Qt::CopyAction | Qt::LinkAction, Qt::CopyAction);
        }
    }

    void initDragThumbnailProvider() {
        mDragThumbnailProvider = new ThumbnailProvider();
        QObject::connect(mDragThumbnailProvider, &ThumbnailProvider::thumbnailLoaded,
                         q, &DocumentView::dragThumbnailLoaded);
        QObject::connect(mDragThumbnailProvider, &ThumbnailProvider::thumbnailLoadingFailed,
                         q, &DocumentView::dragThumbnailLoadingFailed);
    }

    void startDragIfSensible()
    {
        if (q->document()->loadingState() == Document::LoadingFailed) {
            return;
        }

        if (q->currentTool()) {
            return;
        }

        if (mDrag) {
            mDrag->deleteLater();
        }
        mDrag = new QDrag(q);
        const auto itemList = KFileItemList({q->document()->url()});
        mDrag->setMimeData(MimeTypeUtils::selectionMimeData(itemList, MimeTypeUtils::DropTarget));

        if (q->document()->isModified()) {
            setDragPixmap(QPixmap::fromImage(q->document()->image()));
            executeDrag();
        } else {
            // Drag is triggered on success or failure of thumbnail generation
            if (mDragThumbnailProvider.isNull()) {
                initDragThumbnailProvider();
            }
            mDragThumbnailProvider->appendItems(itemList);
        }
    }

    QPointF cursorPosition() {
        const QGraphicsScene* sc = q->scene();
        if (sc) {
            const auto views = sc->views();
            for (const QGraphicsView* view : views) {
                if (view->underMouse()) {
                    return q->mapFromScene(view->mapFromGlobal(QCursor::pos()));
                }
            }
        }
        return QPointF(-1, -1);
    }
};

DocumentView::DocumentView(QGraphicsScene* scene)
: d(new DocumentViewPrivate)
{
    setFlag(ItemIsFocusable);
    setFlag(ItemIsSelectable);
    setFlag(ItemClipsChildrenToShape);

    d->q = this;
    d->mLoadingIndicator = nullptr;
    d->mBirdEyeView = nullptr;
    d->mCurrent = false;
    d->mCompareMode = false;
    d->controlWheelAccumulatedDelta = 0;
    d->mDragStartPosition = QPointF(0, 0);
    d->mDrag = nullptr;

    // We use an opacity effect instead of using the opacity property directly, because the latter operates at
    // the painter level, which means if you draw multiple layers in paint(), all layers get the specified
    // opacity, resulting in all layers being visible when 0 < opacity < 1.
    // QGraphicsEffects on the other hand, operate after all painting is done, therefore 'flattening' all layers.
    // This is important for fade effects, where we don't want any background layers visible during the fade.
    d->mOpacityEffect = new QGraphicsOpacityEffect(this);
    d->mOpacityEffect->setOpacity(0);
    setGraphicsEffect(d->mOpacityEffect);

    scene->addItem(this);

    d->setupHud();
    d->setCurrentAdapter(new EmptyAdapter);

    setAcceptDrops(true);

    connect(DocumentFactory::instance(), &DocumentFactory::documentChanged, this, [this]() {
        d->updateCaption();
    });
}

DocumentView::~DocumentView()
{
    delete d->mDragThumbnailProvider;
    delete d->mDrag;
    delete d;
}

void DocumentView::createAdapterForDocument()
{
    const MimeTypeUtils::Kind documentKind = d->mDocument->kind();
    if (d->mAdapter && documentKind == d->mAdapter->kind() && documentKind != MimeTypeUtils::KIND_UNKNOWN) {
        // Do not reuse for KIND_UNKNOWN: we may need to change the message
        LOG("Reusing current adapter");
        return;
    }
    AbstractDocumentViewAdapter* adapter = nullptr;
    switch (documentKind) {
    case MimeTypeUtils::KIND_RASTER_IMAGE:
        adapter = new RasterImageViewAdapter;
        break;
    case MimeTypeUtils::KIND_SVG_IMAGE:
        adapter = new SvgViewAdapter;
        break;
    case MimeTypeUtils::KIND_VIDEO:
        adapter = new VideoViewAdapter;
        connect(adapter, SIGNAL(videoFinished()),
                SIGNAL(videoFinished()));
        break;
    case MimeTypeUtils::KIND_UNKNOWN:
        adapter = new MessageViewAdapter;
        static_cast<MessageViewAdapter*>(adapter)->setErrorMessage(i18n("Gwenview does not know how to display this kind of document"));
        break;
    default:
        qWarning() << "should not be called for documentKind=" << documentKind;
        adapter = new MessageViewAdapter;
        break;
    }

    d->setCurrentAdapter(adapter);
}

void DocumentView::openUrl(const QUrl &url, const DocumentView::Setup& setup)
{
    if (d->mDocument) {
        if (url == d->mDocument->url()) {
            return;
        }
        disconnect(d->mDocument.data(), nullptr, this, nullptr);
    }
    d->mSetup = setup;
    d->mDocument = DocumentFactory::instance()->load(url);
    connect(d->mDocument.data(), SIGNAL(busyChanged(QUrl,bool)), SLOT(slotBusyChanged(QUrl,bool)));
    connect(d->mDocument.data(), &Document::modified, this, [this]() {
        d->updateZoomSnapValues();
    });

    if (d->mDocument->loadingState() < Document::KindDetermined) {
        MessageViewAdapter* messageViewAdapter = qobject_cast<MessageViewAdapter*>(d->mAdapter.data());
        if (messageViewAdapter) {
            messageViewAdapter->setInfoMessage(QString());
        }
        d->showLoadingIndicator();
        connect(d->mDocument.data(), SIGNAL(kindDetermined(QUrl)),
                SLOT(finishOpenUrl()));
    } else {
        QMetaObject::invokeMethod(this, "finishOpenUrl", Qt::QueuedConnection);
    }
    d->setupBirdEyeView();
}

void DocumentView::finishOpenUrl()
{
    disconnect(d->mDocument.data(), SIGNAL(kindDetermined(QUrl)),
               this, SLOT(finishOpenUrl()));
    GV_RETURN_IF_FAIL(d->mDocument->loadingState() >= Document::KindDetermined);

    if (d->mDocument->loadingState() == Document::LoadingFailed) {
        slotLoadingFailed();
        return;
    }
    createAdapterForDocument();

    connect(d->mDocument.data(), SIGNAL(loadingFailed(QUrl)),
            SLOT(slotLoadingFailed()));
    d->mAdapter->setDocument(d->mDocument);
    d->updateCaption();
}

void DocumentView::loadAdapterConfig()
{
    d->mAdapter->loadConfig();
}

RasterImageView* DocumentView::imageView() const
{
    return d->mAdapter->rasterImageView();
}

void DocumentView::slotCompleted()
{
    d->hideLoadingIndicator();
    d->updateCaption();
    d->updateZoomSnapValues();
    if (!d->mAdapter->zoomToFit() || !d->mAdapter->zoomToFill()) {
        qreal min = minimumZoom();
        if (d->mAdapter->zoom() < min) {
            d->mAdapter->setZoom(min);
        }
    }
    emit completed();
}

DocumentView::Setup DocumentView::setup() const
{
    Setup setup;
    if (d->mAdapter->canZoom()) {
        setup.valid = true;
        setup.zoomToFit = zoomToFit();
        setup.zoomToFill = zoomToFill();
        if (!setup.zoomToFit && !setup.zoomToFill) {
            setup.zoom = zoom();
            setup.position = position();
        }
    }
    return setup;
}

void DocumentView::slotLoadingFailed()
{
    d->hideLoadingIndicator();
    MessageViewAdapter* adapter = new MessageViewAdapter;
    adapter->setDocument(d->mDocument);
    QString message = xi18n("Loading <filename>%1</filename> failed", d->mDocument->url().fileName());
    adapter->setErrorMessage(message, d->mDocument->errorString());
    d->setCurrentAdapter(adapter);
    emit completed();
}

bool DocumentView::canZoom() const
{
    return d->mAdapter->canZoom();
}

void DocumentView::setZoomToFit(bool on)
{
    if (on == d->mAdapter->zoomToFit()) {
        return;
    }
    d->mAdapter->setZoomToFit(on);
}

void DocumentView::toggleZoomToFit() {
    const bool zoomToFitOn = d->mAdapter->zoomToFit();
    d->mAdapter->setZoomToFit(!zoomToFitOn);
    if (zoomToFitOn) {
        d->setZoom(1., d->cursorPosition());
    }
}

void DocumentView::setZoomToFill(bool on)
{
    if (on == d->mAdapter->zoomToFill()) {
        return;
    }
    d->mAdapter->setZoomToFill(on, d->cursorPosition());
}

void DocumentView::toggleZoomToFill() {
    const bool zoomToFillOn = d->mAdapter->zoomToFill();
    d->mAdapter->setZoomToFill(!zoomToFillOn, d->cursorPosition());
    if (zoomToFillOn) {
        d->setZoom(1., d->cursorPosition());
    }
}

bool DocumentView::zoomToFit() const
{
    return d->mAdapter->zoomToFit();
}

bool DocumentView::zoomToFill() const
{
    return d->mAdapter->zoomToFill();
}

void DocumentView::zoomActualSize()
{
    d->uncheckZoomToFit();
    d->uncheckZoomToFill();
    d->mAdapter->setZoom(1., d->cursorPosition());
}

void DocumentView::zoomIn(QPointF center)
{
    if (center == QPointF(-1, -1)) {
        center = d->cursorPosition();
    }
    qreal currentZoom = d->mAdapter->zoom();

    Q_FOREACH(qreal zoom, d->mZoomSnapValues) {
        if (zoom > currentZoom + REAL_DELTA) {
            d->setZoom(zoom, center);
            return;
        }
    }
}

void DocumentView::zoomOut(QPointF center)
{
    if (center == QPointF(-1, -1)) {
        center = d->cursorPosition();
    }
    qreal currentZoom = d->mAdapter->zoom();

    QListIterator<qreal> it(d->mZoomSnapValues);
    it.toBack();
    while (it.hasPrevious()) {
        qreal zoom = it.previous();
        if (zoom < currentZoom - REAL_DELTA) {
            d->setZoom(zoom, center);
            return;
        }
    }
}

void DocumentView::slotZoomChanged(qreal zoom)
{
    d->updateCaption();
    zoomChanged(zoom);
}

void DocumentView::setZoom(qreal zoom)
{
    d->setZoom(zoom);
}

qreal DocumentView::zoom() const
{
    return d->mAdapter->zoom();
}

void DocumentView::resizeEvent(QGraphicsSceneResizeEvent *event)
{
    d->resizeAdapterWidget();
    d->updateZoomSnapValues();
    QGraphicsWidget::resizeEvent(event);
}

void DocumentView::mousePressEvent(QGraphicsSceneMouseEvent* event)
{
    QGraphicsWidget::mousePressEvent(event);

    if (d->mAdapter->canZoom() && event->button() == Qt::MiddleButton) {
        if (event->modifiers() == Qt::NoModifier) {
            toggleZoomToFit();
        } else if (event->modifiers() == Qt::SHIFT) {
            toggleZoomToFill();
        }
    }
}

void DocumentView::wheelEvent(QGraphicsSceneWheelEvent* event)
{
    if (d->mAdapter->canZoom() && event->modifiers() & Qt::ControlModifier) {
        d->controlWheelAccumulatedDelta += event->delta();
        // Ctrl + wheel => zoom in or out
        if (d->controlWheelAccumulatedDelta >= QWheelEvent::DefaultDeltasPerStep) {
            zoomIn(event->pos());
            d->controlWheelAccumulatedDelta = 0;
        } else if (d->controlWheelAccumulatedDelta <= -QWheelEvent::DefaultDeltasPerStep) {
            zoomOut(event->pos());
            d->controlWheelAccumulatedDelta = 0;
        }
        return;
    }
    if (GwenviewConfig::mouseWheelBehavior() == MouseWheelBehavior::Browse
        && event->modifiers() == Qt::NoModifier) {
        d->controlWheelAccumulatedDelta += event->delta();
        // Browse with mouse wheel
        if (d->controlWheelAccumulatedDelta >= QWheelEvent::DefaultDeltasPerStep) {
            previousImageRequested();
            d->controlWheelAccumulatedDelta = 0;
        } else if (d->controlWheelAccumulatedDelta <= -QWheelEvent::DefaultDeltasPerStep) {
            nextImageRequested();
            d->controlWheelAccumulatedDelta = 0;
        }
        return;
    }
    // Scroll
    qreal dx = 0;
    // 16 = pixels for one line
    // 120: see QWheelEvent::delta() doc
    qreal dy = -qApp->wheelScrollLines() * 16 * event->delta() / 120;
    if (event->orientation() == Qt::Horizontal) {
        qSwap(dx, dy);
    }
    d->mAdapter->setScrollPos(d->mAdapter->scrollPos() + QPointF(dx, dy));
}

void DocumentView::contextMenuEvent(QGraphicsSceneContextMenuEvent* event)
{
    // Filter out context menu if Ctrl is down to avoid showing it when
    // zooming out with Ctrl + Right button
    if (event->modifiers() != Qt::ControlModifier) {
        contextMenuRequested();
    }
}

void DocumentView::paint(QPainter* painter, const QStyleOptionGraphicsItem* /*option*/, QWidget* /*widget*/)
{
    // Fill background manually, because setAutoFillBackground(true) fill with QPalette::Window,
    // but our palettes use QPalette::Base for the background color/texture
    painter->fillRect(rect(), palette().base());

    // Selection indicator/highlight
    if (d->mCompareMode && d->mCurrent) {
        painter->save();
        painter->setBrush(Qt::NoBrush);
        painter->setPen(QPen(palette().highlight().color(), 2));
        painter->setRenderHint(QPainter::Antialiasing);
        const QRectF visibleRectF = mapRectFromItem(d->mAdapter->widget(), d->mAdapter->visibleDocumentRect());
        // Round the point and size independently. This is different than calling toRect(),
        // and is necessary to keep consistent rects, otherwise the selection rect can be
        // drawn 1 pixel too big or small.
        const QRect visibleRect = QRect(visibleRectF.topLeft().toPoint(), visibleRectF.size().toSize());
        const QRect selectionRect = visibleRect.adjusted(-1, -1, 1, 1);
        painter->drawRoundedRect(selectionRect, 3, 3);
        painter->restore();
    }
}

void DocumentView::slotBusyChanged(const QUrl&, bool busy)
{
    if (busy) {
        d->showLoadingIndicator();
    } else {
        d->hideLoadingIndicator();
    }
}

qreal DocumentView::minimumZoom() const
{
    // There is no point zooming out less than zoomToFit, but make sure it does
    // not get too small either
    return qBound(qreal(0.001), d->mAdapter->computeZoomToFit(), qreal(1.));
}

void DocumentView::setCompareMode(bool compare)
{
    d->mCompareMode = compare;
    if (compare) {
        d->mHud->show();
        d->mHud->setZValue(1);
    } else {
        d->mHud->hide();
    }
}

void DocumentView::setCurrent(bool value)
{
    d->mCurrent = value;
    if (value) {
        d->mAdapter->widget()->setFocus();
        d->updateCaption();
    }
    update();
}

bool DocumentView::isCurrent() const
{
    return d->mCurrent;
}

QPoint DocumentView::position() const
{
    return d->mAdapter->scrollPos().toPoint();
}

void DocumentView::setPosition(const QPoint& pos)
{
    d->mAdapter->setScrollPos(pos);
}

Document::Ptr DocumentView::document() const
{
    return d->mDocument;
}

QUrl DocumentView::url() const
{
    Document::Ptr doc = d->mDocument;
    return doc ? doc->url() : QUrl();
}

void DocumentView::emitHudDeselectClicked()
{
    hudDeselectClicked(this);
}

void DocumentView::emitHudTrashClicked()
{
    hudTrashClicked(this);
}

void DocumentView::emitFocused()
{
    focused(this);
}

void DocumentView::setGeometry(const QRectF& rect)
{
    QGraphicsWidget::setGeometry(rect);
    if (d->mBirdEyeView) {
        d->mBirdEyeView->slotZoomOrSizeChanged();
    }
}

void DocumentView::moveTo(const QRect& rect)
{
    if (d->mMoveAnimation) {
        d->mMoveAnimation.data()->setEndValue(rect);
    } else {
        setGeometry(rect);
    }
}

void DocumentView::moveToAnimated(const QRect& rect)
{
    QPropertyAnimation* anim = new QPropertyAnimation(this, "geometry");
    anim->setStartValue(geometry());
    anim->setEndValue(rect);
    anim->setDuration(DocumentView::AnimDuration);
    connect(anim, SIGNAL(finished()), SIGNAL(isAnimatedChanged()));
    d->mMoveAnimation = anim;
    isAnimatedChanged();
    anim->start(QAbstractAnimation::DeleteWhenStopped);
}

QPropertyAnimation* DocumentView::fadeIn()
{
    d->fadeTo(1);
    return d->mFadeAnimation.data();
}

void DocumentView::fadeOut()
{
    d->fadeTo(0);
}

void DocumentView::slotFadeInFinished()
{
    fadeInFinished(this);
}

bool DocumentView::isAnimated() const
{
    return d->mMoveAnimation || d->mFadeAnimation;
}

bool DocumentView::sceneEventFilter(QGraphicsItem*, QEvent* event)
{
    if (event->type() == QEvent::GraphicsSceneMousePress) {
        const QGraphicsSceneMouseEvent* mouseEvent = static_cast<QGraphicsSceneMouseEvent*>(event);
        if (mouseEvent->button() == Qt::LeftButton) {
            d->mDragStartPosition = mouseEvent->pos();
        }
        QMetaObject::invokeMethod(this, "emitFocused", Qt::QueuedConnection);
    } else if (event->type() == QEvent::GraphicsSceneHoverMove) {
        if (d->mBirdEyeView) {
            d->mBirdEyeView->onMouseMoved();
        }
    } else if (event->type() == QEvent::GraphicsSceneMouseMove) {
        const QGraphicsSceneMouseEvent* mouseEvent = static_cast<QGraphicsSceneMouseEvent*>(event);
        const qreal dragDistance = (mouseEvent->pos() - d->mDragStartPosition).manhattanLength();
        const qreal minDistanceToStartDrag = QGuiApplication::styleHints()->startDragDistance();
        if (!d->canPan() && dragDistance >= minDistanceToStartDrag) {
            d->startDragIfSensible();
        }
    }
    return false;
}

AbstractRasterImageViewTool* DocumentView::currentTool() const
{
    return imageView() ? imageView()->currentTool() : nullptr;
}

int DocumentView::sortKey() const
{
    return d->mSortKey;
}

void DocumentView::setSortKey(int sortKey)
{
    d->mSortKey = sortKey;
}

void DocumentView::hideAndDeleteLater()
{
    hide();
    deleteLater();
}

void DocumentView::setGraphicsEffectOpacity(qreal opacity)
{
    d->mOpacityEffect->setOpacity(opacity);
}

void DocumentView::dragEnterEvent(QGraphicsSceneDragDropEvent* event)
{
    QGraphicsWidget::dragEnterEvent(event);

    const auto urls = KUrlMimeData::urlsFromMimeData(event->mimeData());
    bool acceptDrag = !urls.isEmpty();
    if (urls.size() == 1 && urls.first() == url()) {
        // Do not allow dragging a single image onto itself
        acceptDrag = false;
    }
    event->setAccepted(acceptDrag);
}

void DocumentView::dropEvent(QGraphicsSceneDragDropEvent* event)
{
    QGraphicsWidget::dropEvent(event);
    // Since we're capturing drops in View mode, we only support one url
    const QUrl url = event->mimeData()->urls().first();
    if (UrlUtils::urlIsDirectory(url)) {
        emit openDirUrlRequested(url);
    } else {
        emit openUrlRequested(url);
    }
}

void DocumentView::dragThumbnailLoaded(const KFileItem& item, const QPixmap& pix)
{
    d->setDragPixmap(pix);
    d->executeDrag();
    d->mDragThumbnailProvider->removeItems(KFileItemList({item}));
}

void DocumentView::dragThumbnailLoadingFailed(const KFileItem& item)
{
    d->executeDrag();
    d->mDragThumbnailProvider->removeItems(KFileItemList({item}));
}

} // namespace
