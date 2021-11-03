package com.wtuadn.jnitool;

import android.content.Context;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.content.pm.Signature;
import android.util.Log;

/**
 * Created by wtuadn on 2017/3/9.
 */

public class JNITool {

    public static void initialize(Context context) {
        System.loadLibrary("jni_tool");
        jniinitialize(context);
    }

    private static native void jniinitialize(Context context);

    private static native String jniencrypt(byte[] bytes);

    private static native byte[] jnidecrypt(String str);

    public static native String pwdMD5(String str);

    public static String encrypt(String str) {
        return jniencrypt(str.getBytes());
    }

    public static String decrypt(String str) {
        return new String(jnidecrypt(str));
    }

    //获取签名
    public static int getSignature(Context context) {
        try {
            PackageInfo packageInfo = context.getPackageManager().getPackageInfo(context.getPackageName(), PackageManager.GET_SIGNATURES);

            Signature sign = packageInfo.signatures[0];
            return sign.hashCode();
        }
        catch (Exception e) {
            e.printStackTrace();
        }
        return -1;
    }
}
