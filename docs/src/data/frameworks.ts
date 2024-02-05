export type Framework =
  | 'android'
  | 'angular'
  | 'flutter'
  | 'react'
  | 'react-native'
  | 'swift'
  | 'vue';
export type Frameworks = Framework[];

export const FRAMEWORKS: Frameworks = [
  'android',
  'angular',
  'flutter',
  'react',
  'react-native',
  'swift',
  'vue',
];

export const FRAMEWORK_DISPLAY_NAMES: Record<Framework, string> = {
  android: 'Android',
  angular: 'Angular',
  flutter: 'Flutter',
  react: 'React',
  'react-native': 'React Native',
  swift: 'Swift',
  vue: 'Vue',
};

export const MAJOR_VERSIONS: Record<string, number[]> = {
  angular: [5, 4, 3, 2, 1],
  'aws-amplify': [6, 5, 4, 3, 2, 1],
  react: [6, 5, 4, 3, 2, 1],
  'react-native': [2, 1],
  vue: [4, 3, 2, 1],
};

// React Native requires direct installation of dependencies with native modules
export const REACT_NATIVE_DEPENDENCIES =
  '@aws-amplify/react-native react-native-safe-area-context @react-native-community/netinfo @react-native-async-storage/async-storage react-native-get-random-values react-native-url-polyfill';

export const FRAMEWORK_INSTALL_SCRIPTS = {
  react: 'npm i @aws-amplify/ui-react aws-amplify',
  vue: 'npm i @aws-amplify/ui-vue aws-amplify',
  angular: 'npm i @aws-amplify/ui-angular aws-amplify',
  flutter: 'flutter pub add amplify_authenticator',
  android: "implementation 'com.amplifyframework.ui:liveness:1.2.1'",
  'react-native': `npm i @aws-amplify/ui-react-native aws-amplify ${REACT_NATIVE_DEPENDENCIES}`,
};
