#include <jni.h>
#include <stdint.h>
extern int sirinStart(int, const char *);
extern int sirinCommit(int);
extern void sirinStop(int);
extern int sirinSocket(int, int);
extern int sirinStats(int, int64_t *, int64_t *, int64_t *);
extern int sirinProbeStart(const char *);
extern int sirinProbeSample(int,const char *,const char *,int64_t *,int64_t *,int64_t *);
extern int sirinEndpoint(int,const char *);

JNIEXPORT jint JNICALL Java_org_sirinvpn_client_WireGuard_start(JNIEnv *env, jobject self, jint fd, jstring configuration) {
    const char *value = (*env)->GetStringUTFChars(env, configuration, 0);
    if (!value) return -1;
    int result = sirinStart(fd, value);
    (*env)->ReleaseStringUTFChars(env, configuration, value);
    return result;
}
JNIEXPORT jboolean JNICALL Java_org_sirinvpn_client_WireGuard_commit(JNIEnv *env, jobject self, jint handle) { return sirinCommit(handle) == 1; }
JNIEXPORT jint JNICALL Java_org_sirinvpn_client_WireGuard_probeStart(JNIEnv *env,jobject self,jstring configuration) {
    const char *value=(*env)->GetStringUTFChars(env,configuration,0);if (!value) return -1;
    int result=sirinProbeStart(value);(*env)->ReleaseStringUTFChars(env,configuration,value);return result;
}
JNIEXPORT jboolean JNICALL Java_org_sirinvpn_client_WireGuard_endpoint(JNIEnv *env,jobject self,jint handle,jstring configuration) {
    const char *value=(*env)->GetStringUTFChars(env,configuration,0);if (!value) return 0;
    int result=sirinEndpoint(handle,value);(*env)->ReleaseStringUTFChars(env,configuration,value);return result==1;
}
JNIEXPORT jlongArray JNICALL Java_org_sirinvpn_client_WireGuard_probeSample(JNIEnv *env,jobject self,jint handle,jstring source,jstring destination) {
    const char *src=(*env)->GetStringUTFChars(env,source,0);if (!src) return NULL;
    const char *dst=(*env)->GetStringUTFChars(env,destination,0);if (!dst) {(*env)->ReleaseStringUTFChars(env,source,src);return NULL;}
    int64_t received=0,latency=0,jitter=0;
    int ok=sirinProbeSample(handle,src,dst,&received,&latency,&jitter);
    (*env)->ReleaseStringUTFChars(env,source,src);(*env)->ReleaseStringUTFChars(env,destination,dst);if (!ok) return NULL;
    jlong values[3]={received,latency,jitter};jlongArray result=(*env)->NewLongArray(env,3);
    if(result) (*env)->SetLongArrayRegion(env,result,0,3,values);return result;
}
JNIEXPORT void JNICALL Java_org_sirinvpn_client_WireGuard_stop(JNIEnv *env, jobject self, jint handle) { sirinStop(handle); }
JNIEXPORT jint JNICALL Java_org_sirinvpn_client_WireGuard_socket4(JNIEnv *env, jobject self, jint handle) { return sirinSocket(handle, 4); }
JNIEXPORT jint JNICALL Java_org_sirinvpn_client_WireGuard_socket6(JNIEnv *env, jobject self, jint handle) { return sirinSocket(handle, 6); }
JNIEXPORT jlongArray JNICALL Java_org_sirinvpn_client_WireGuard_statistics(JNIEnv *env, jobject self, jint handle) {
    int64_t rx=0, tx=0, handshake=0;
    if (!sirinStats(handle, &rx, &tx, &handshake)) return NULL;
    jlong values[3] = {rx, tx, handshake};
    jlongArray result = (*env)->NewLongArray(env, 3);
    if (result) (*env)->SetLongArrayRegion(env, result, 0, 3, values);
    return result;
}
