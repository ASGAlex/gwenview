// vim: set tabstop=4 shiftwidth=4 noexpandtab:
/*
Gwenview: an image viewer
Copyright 2007 Aurélien Gâteau <aurelien.gateau@free.fr>

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
Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.

*/
// Self
#include "loadingdocumentimpl.moc"

// Qt
#include <QBuffer>
#include <QByteArray>
#include <QFile>
#include <QFuture>
#include <QFutureWatcher>
#include <QImage>
#include <QImageReader>
#include <QPointer>
#include <QtConcurrentRun>

// KDE
#include <kdebug.h>
#include <kio/job.h>
#include <kio/jobclasses.h>
#include <kurl.h>

// Local
#include "document.h"
#include "documentloadedimpl.h"
#include "emptydocumentimpl.h"
#include "exiv2imageloader.h"
#include "imageutils.h"
#include "jpegcontent.h"
#include "jpegdocumentloadedimpl.h"
#include "orientation.h"
#include "urlutils.h"

namespace Gwenview {

#undef ENABLE_LOG
#undef LOG
//#define ENABLE_LOG
#ifdef ENABLE_LOG
#define LOG(x) kDebug() << x
#else
#define LOG(x) ;
#endif


struct LoadingDocumentImplPrivate {
	LoadingDocumentImpl* mImpl;
	QPointer<KIO::TransferJob> mTransferJob;
	QFuture<bool> mMetaDataFuture;
	QFutureWatcher<bool> mMetaDataFutureWatcher;
	QFuture<void> mImageDataFuture;
	QFutureWatcher<void> mImageDataFutureWatcher;

	// If != 0, this means we need to load an image at zoom =
	// 1/mImageDataInvertedZoom
	int mImageDataInvertedZoom;

	bool mMetaDataLoaded;
	QByteArray mData;
	QByteArray mFormat;
	QSize mImageSize;
	Exiv2::Image::AutoPtr mExiv2Image;
	JpegContent* mJpegContent;
	QImage mImage;

	void startLoading() {
		Q_ASSERT(!mMetaDataLoaded);
		mMetaDataFuture = QtConcurrent::run(this, &LoadingDocumentImplPrivate::loadMetaData);
		mMetaDataFutureWatcher.setFuture(mMetaDataFuture);
	}

	void startImageDataLoading() {
		LOG("");
		Q_ASSERT(mMetaDataLoaded);
		Q_ASSERT(mImageDataInvertedZoom != 0);
		mImageDataFuture = QtConcurrent::run(this, &LoadingDocumentImplPrivate::loadImageData);
		mImageDataFutureWatcher.setFuture(mImageDataFuture);
	}

	bool loadMetaData() {
		QBuffer buffer;
		buffer.setBuffer(&mData);
		buffer.open(QIODevice::ReadOnly);
		QImageReader reader(&buffer);
		mFormat = reader.format();
		if (mFormat.isEmpty()) {
			return false;
		}

		Exiv2ImageLoader loader;
		if (loader.load(mData)) {
			mExiv2Image = loader.popImage();
		}

		if (mFormat == "jpeg" && mExiv2Image.get()) {
			mJpegContent = new JpegContent();
			if (!mJpegContent->loadFromData(mData, mExiv2Image.get())) {
				return false;
			}

			// Use the size from JpegContent, as its correctly transposed if the
			// image has been rotated
			mImageSize = mJpegContent->size();
		} else {
			mImageSize = reader.size();
		}

		return true;
	}

	void loadImageData() {
		QBuffer buffer;
		buffer.setBuffer(&mData);
		buffer.open(QIODevice::ReadOnly);
		QImageReader reader(&buffer);

		LOG("mImageDataInvertedZoom=" << mImageDataInvertedZoom);
		if (mImageSize.isValid()
			&& mImageDataInvertedZoom != 1
			&& reader.supportsOption(QImageIOHandler::ScaledSize)
			)
		{
			// Do not use mImageSize here: QImageReader needs a non-transposed
			// image size
			QSize size = reader.size() / mImageDataInvertedZoom;
			LOG("Setting scaled size to" << size);
			reader.setScaledSize(size);
		}

		bool ok = reader.read(&mImage);
		if (!ok) {
			return;
		}

		if (mJpegContent) {
			Gwenview::Orientation orientation = mJpegContent->orientation();
			QMatrix matrix = ImageUtils::transformMatrix(orientation);
			mImage = mImage.transformed(matrix);
		}
	}
};


LoadingDocumentImpl::LoadingDocumentImpl(Document* document)
: AbstractDocumentImpl(document)
, d(new LoadingDocumentImplPrivate) {
	d->mImpl = this;
	d->mMetaDataLoaded = false;
	d->mJpegContent = 0;
	d->mImageDataInvertedZoom = 0;

	connect(&d->mMetaDataFutureWatcher, SIGNAL(finished()),
		SLOT(slotMetaDataLoaded()) );

	connect(&d->mImageDataFutureWatcher, SIGNAL(finished()),
		SLOT(slotImageLoaded()) );
}


LoadingDocumentImpl::~LoadingDocumentImpl() {
	LOG("");
	if (d->mTransferJob) {
		d->mTransferJob->kill();
	}
	delete d;
}

void LoadingDocumentImpl::init() {
	KUrl url = document()->url();

	if (UrlUtils::urlIsFastLocalFile(url)) {
		// Load file content directly
		QFile file(url.path());
		if (!file.open(QIODevice::ReadOnly)) {
			kWarning() << "Couldn't open" << url;
			switchToImpl(new EmptyDocumentImpl(document()));
			return;
		}
		d->mData = file.readAll();
		d->startLoading();
	} else {
		// Transfer file via KIO
		d->mTransferJob = KIO::get(document()->url());
		connect(d->mTransferJob, SIGNAL(data(KIO::Job*, const QByteArray&)),
			SLOT(slotDataReceived(KIO::Job*, const QByteArray&)) );
		connect(d->mTransferJob, SIGNAL(result(KJob*)),
			SLOT(slotTransferFinished(KJob*)) );
		d->mTransferJob->start();
	}
}


void LoadingDocumentImpl::loadImage(int invertedZoom) {
	if (d->mImageDataInvertedZoom == invertedZoom) {
		LOG("Already loading an image at invertedZoom=" << invertedZoom);
		return;
	}
	d->mImageDataFutureWatcher.waitForFinished();
	d->mImageDataInvertedZoom = invertedZoom;

	// FIXME: Document reason for test (remote download)
	if (!d->mMetaDataFutureWatcher.isRunning() && d->mMetaDataLoaded) {
		d->startImageDataLoading();
	}
}


void LoadingDocumentImpl::slotDataReceived(KIO::Job*, const QByteArray& chunk) {
	d->mData.append(chunk);
}


void LoadingDocumentImpl::slotTransferFinished(KJob* job) {
	if (job->error()) {
		//FIXME: Better error handling
		kWarning() << job->errorString();
		switchToImpl(new EmptyDocumentImpl(document()));
		return;
	}
	d->startLoading();
}


bool LoadingDocumentImpl::isMetaDataLoaded() const {
	return d->mMetaDataLoaded;
}


Document::LoadingState LoadingDocumentImpl::loadingState() const {
	if (d->mMetaDataLoaded) {
		return Document::MetaDataLoaded;
	} else {
		return Document::Loading;
	}
}


void LoadingDocumentImpl::slotMetaDataLoaded() {
	Q_ASSERT(!d->mMetaDataFuture.isRunning());
	if (!d->mMetaDataFuture.result()) {
		kWarning() << document()->url() << "Loading metadata failed";
		emit loadingFailed();
		switchToImpl(new EmptyDocumentImpl(document()));
		return;
	}

	setDocumentFormat(d->mFormat);
	setDocumentImageSize(d->mImageSize);
	setDocumentExiv2Image(d->mExiv2Image);

	d->mMetaDataLoaded = true;

	// Start image loading if necessary
	if (d->mImageDataInvertedZoom != 0) {
		d->startImageDataLoading();
	}
}


void LoadingDocumentImpl::slotImageLoaded() {
	Q_ASSERT(!d->mImage.isNull());

	if (d->mImageDataInvertedZoom != 1 && d->mImage.size() != d->mImageSize) {
		// We loaded a down sampled image
		setDocumentDownSampledImage(d->mImage, d->mImageDataInvertedZoom);
		return;
	}

	setDocumentImage(d->mImage);
	imageRectUpdated(d->mImage.rect());
	emit loaded();
	if (d->mJpegContent) {
		JpegDocumentLoadedImpl* impl = new JpegDocumentLoadedImpl(
			document(),
			d->mJpegContent);
		switchToImpl(impl);
	} else {
		switchToImpl(new DocumentLoadedImpl(document()));
	}
}


Document::SaveResult LoadingDocumentImpl::save(const KUrl&, const QByteArray&) {
	return Document::SR_OtherError;
}

void LoadingDocumentImpl::setImage(const QImage&) {
	kWarning() << " should not be called\n";
}

} // namespace
