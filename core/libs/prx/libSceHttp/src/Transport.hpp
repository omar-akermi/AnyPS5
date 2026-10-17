#ifndef CORE_LIBS_PRX_LIBSCEHTTP_SRC_TRANSPORT_HPP
#define CORE_LIBS_PRX_LIBSCEHTTP_SRC_TRANSPORT_HPP

int HttpNextHandle_nid_no_patch();
void HttpContextStarted_nid_no_patch(int id);
void HttpContextStopped_nid_no_patch(int id);
void HttpForgetCallback_nid_no_patch(int id);
bool HttpHasCallback_nid_no_patch(int id);
bool HttpHasObject_nid_no_patch(int id);

#endif
