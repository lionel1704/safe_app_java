#!/usr/bin/env bash

version=0.1.0
package='safe-app-android'
flavour='nonMock'
if [ $1 == 'true' ]
then
    package='safe-app-android-dev'
    flavour='mock'
fi
filePaths=("build/libs/safe-app-android-javadoc.jar.asc" "build/libs/safe-app-android-sources.jar.asc" "build/outputs/aar/safe-app-android-$flavour-release-$version.aar.asc" "build/publications/mavenJava/pom-default.xml.asc")
targetFiles=("$package-$version-javadoc.jar.asc" "$package-$version-sources.jar.asc" "$package-$version.aar.asc" "$package-$version.pom.asc")
for i in ${!filePaths[@]}
do
    echo "${filePaths[$i]}"
    echo "${targetFiles[$i]}"
    curl -T "${filePaths[$i]}" -u$2:$3 "https://api.bintray.com/content/lionel1704/newTest/$package/$version/net/maidsafe/$package/$version/${targetFiles[$i]}"
done
