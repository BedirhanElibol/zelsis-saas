import type { RuleCase } from '../cases';
import type { CodeFile } from '../../../lib/scanner-engine';

const f = (path: string, content: string): CodeFile[] => [{ path, content }];

export const CASES: RuleCase[] = [
  {
    ruleIds: [9351],
    name: 'STORE-01 com.example applicationId vs a real reverse-domain id',
    detects: f('android/app/build.gradle', "android {\n    namespace 'com.example.invoices'\n    defaultConfig {\n        applicationId 'com.example.invoices'\n        targetSdkVersion 35\n    }\n}\n"),
    ignores: f('android/app/build.gradle', "android {\n    namespace 'com.acme.invoices'\n    defaultConfig {\n        applicationId 'com.acme.invoices'\n        targetSdkVersion 35\n    }\n}\n"),
  },
  {
    ruleIds: [9351],
    name: 'STORE-01 React Native template bundle id in Expo config',
    detects: f('app.json', '{\n  "expo": {\n    "name": "Invoices",\n    "ios": { "bundleIdentifier": "org.reactjs.native.example.Invoices" }\n  }\n}\n'),
    ignores: f('app.json', '{\n  "expo": {\n    "name": "Invoices",\n    "ios": { "bundleIdentifier": "com.acme.invoices" }\n  }\n}\n'),
  },
  {
    ruleIds: [9352],
    name: 'STORE-02 READ_SMS requested vs the permission removed from a library manifest',
    detects: f('android/app/src/main/AndroidManifest.xml', '<manifest xmlns:android="http://schemas.android.com/apk/res/android">\n    <uses-permission android:name="android.permission.INTERNET" />\n    <uses-permission android:name="android.permission.READ_SMS" />\n</manifest>\n'),
    ignores: f('android/app/src/main/AndroidManifest.xml', '<manifest xmlns:android="http://schemas.android.com/apk/res/android" xmlns:tools="http://schemas.android.com/tools">\n    <uses-permission android:name="android.permission.INTERNET" />\n    <uses-permission android:name="android.permission.READ_SMS" tools:node="remove" />\n</manifest>\n'),
  },
  {
    ruleIds: [9353],
    name: 'STORE-03 targetSdk 33 vs 35',
    detects: f('android/app/build.gradle.kts', 'android {\n    defaultConfig {\n        applicationId = "com.acme.invoices"\n        targetSdk = 33\n    }\n}\n'),
    ignores: f('android/app/build.gradle.kts', 'android {\n    defaultConfig {\n        applicationId = "com.acme.invoices"\n        targetSdk = 35\n    }\n}\n'),
  },
  {
    ruleIds: [9354],
    name: 'STORE-04 empty camera prompt vs one that names the feature',
    detects: f('ios/Invoices/Info.plist', '<dict>\n    <key>NSCameraUsageDescription</key>\n    <string></string>\n</dict>\n'),
    ignores: f('ios/Invoices/Info.plist', '<dict>\n    <key>NSCameraUsageDescription</key>\n    <string>Scan receipts with the camera to add them to an expense.</string>\n</dict>\n'),
  },
];
