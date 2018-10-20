# gwenview
Image viewer for KDE

This repository contains adaptation to make app work on Windows. 
Current version is Applications/18.08.win, look at corresponding branch.

Changes: 
 - rand_r() changed to rand()
 - custom mkdtemp() implementation in fileutils.cpp
 - Semantic search backend (like Baloo) disabled in CMakeLists
 - Kipi plugins disabled in CMakeLists
 - Tags tab removed from start screen. Tab apperance changet to flat
 - Cursor wrap on screen edge turned on in AbstractImageView (like in old versions)
 
 Succesfully tested with [Craft](https://community.kde.org/Craft) on Release and MinSizeRel build configurations.
 
