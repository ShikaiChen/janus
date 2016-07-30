/*! \file   janus_echotest.c
 * \author Lorenzo Miniero <lorenzo@meetecho.com>
 * \copyright GNU General Public License v3
 * \brief  Janus EchoTest plugin
 * \details  This is a trivial EchoTest plugin for Janus, just used to
 * showcase the plugin interface. A peer attaching to this plugin will
 * receive back the same RTP packets and RTCP messages he sends: the
 * RTCP messages, of course, would be modified on the way by the gateway
 * to make sure they are coherent with the involved SSRCs. In order to
 * demonstrate how peer-provided messages can change the behaviour of a
 * plugin, this plugin implements a simple API based on three messages:
 * 
 * 1. a message to enable/disable audio (that is, to tell the plugin
 * whether incoming audio RTP packets need to be sent back or discarded);
 * 2. a message to enable/disable video (that is, to tell the plugin
 * whether incoming video RTP packets need to be sent back or discarded);
 * 3. a message to cap the bitrate (which would modify incoming RTCP
 * REMB messages before sending them back, in order to trick the peer into
 * thinking the available bandwidth is different).
 * 
 * \section echoapi Echo Test API
 * 
 * There's a single unnamed request you can send and it's asynchronous,
 * which means all responses (successes and errors) will be delivered
 * as events with the same transaction. 
 * 
 * The request has to be formatted as follows. All the attributes are
 * optional, so any request can contain a subset of them:
 *
\verbatim
{
	"audio" : true|false,
	"video" : true|false,
	"bitrate" : <numeric bitrate value>,
	"record" : true|false,
	"filename" : <base path/filename to use for the recording>
}
\endverbatim
 *
 * \c audio instructs the plugin to do or do not bounce back audio
 * frames; \c video does the same for video; \c bitrate caps the
 * bandwidth to force on the browser encoding side (e.g., 128000 for
 * 128kbps).
 * 
 * The first request must be sent together with a JSEP offer to
 * negotiate a PeerConnection: a JSEP answer will be provided with
 * the asynchronous response notification. Subsequent requests (e.g., to
 * dynamically manipulate the bitrate while testing) have to be sent
 * without any JSEP payload attached.
 * 
 * A successful request will result in an \c ok event:
 * 
\verbatim
{
	"echotest" : "event",
	"result": "ok"
}
\endverbatim
 * 
 * An error instead will provide both an error code and a more verbose
 * description of the cause of the issue:
 * 
\verbatim
{
	"echotest" : "event",
	"error_code" : <numeric ID, check Macros below>,
	"error" : "<error description as a string>"
}
\endverbatim
 *
 * If the plugin detects a loss of the associated PeerConnection, a
 * "done" notification is triggered to inform the application the Echo
 * Test session is over:
 * 
\verbatim
{
	"echotest" : "event",
	"result": "done"
}
\endverbatim
 *
 * \ingroup plugins
 * \ref plugins
 */

#include "plugin.h"

#include <jansson.h>

#include "../debug.h"
#include "../apierror.h"
#include "../config.h"
#include "../mutex.h"
#include "../record.h"
#include "../rtcp.h"
#include "../utils.h"
#include <stdio.h>
#include <sqlite3.h>
#include <libavcodec/avcodec.h>
#include <libavformat/avformat.h>
#include <libswscale/swscale.h>
#include <libavutil/avutil.h>
#include <libavutil/opt.h>
#include <libavutil/channel_layout.h>
#include <libavutil/common.h>
#include <libavutil/imgutils.h>
#include <libavutil/mathematics.h>
#include <libavutil/samplefmt.h>
/* Plugin information */
#define JANUS_ECHOTEST_VERSION			6
#define JANUS_ECHOTEST_VERSION_STRING	"0.0.6"
#define JANUS_ECHOTEST_DESCRIPTION		"This is a trivial EchoTest plugin for Janus, just used to showcase the plugin interface."
#define JANUS_ECHOTEST_NAME				"JANUS EchoTest plugin"
#define JANUS_ECHOTEST_AUTHOR			"Meetecho s.r.l."
#define JANUS_ECHOTEST_PACKAGE			"janus.plugin.echotest"

typedef struct janus_echotest_rtp_packet
{
	char* data;
	int len;
}janus_echotest_rtp_packet;

typedef struct janus_echotest_incoming_pp 
{
	GList * data;
	janus_mutex mutex;
	gint fir_seq; 
	int need_keyframe; 
} janus_echotest_incoming_pp;

typedef struct janus_vp8_infos
{
	int vp8w;
	int vp8ws;
	int vp8h;
	int vp8hs;
	uint8_t xbit;
	uint8_t sbit;
	uint8_t key;
	uint16_t pid;
	int len;
	char* offset;
} janus_vp8_infos;
GHashTable * pp_publishers = NULL; 
janus_mutex pp_publishers_mutex;

typedef struct janus_pp_rtp_header
{
#if __BYTE_ORDER == __BIG_ENDIAN
	uint16_t version:2;
	uint16_t padding:1;
	uint16_t extension:1;
	uint16_t csrccount:4;
	uint16_t markerbit:1;
	uint16_t type:7;
#elif __BYTE_ORDER == __LITTLE_ENDIAN
	uint16_t csrccount:4;
	uint16_t extension:1;
	uint16_t padding:1;
	uint16_t version:2;
	uint16_t type:7;
	uint16_t markerbit:1;
#endif
	uint16_t seq_number;
	uint32_t timestamp;
	uint32_t ssrc;
	uint32_t csrc[16];
} janus_pp_rtp_header;

typedef struct janus_pp_rtp_header_extension {
	uint16_t type;
	uint16_t length;
} janus_pp_rtp_header_extension;

/* Plugin methods */
janus_plugin *create(void);
int janus_echotest_init(janus_callbacks *callback, const char *config_path);
void janus_echotest_destroy(void);
int janus_echotest_get_api_compatibility(void);
int janus_echotest_get_version(void);
const char *janus_echotest_get_version_string(void);
const char *janus_echotest_get_description(void);
const char *janus_echotest_get_name(void);
const char *janus_echotest_get_author(void);
const char *janus_echotest_get_package(void);
void janus_echotest_create_session(janus_plugin_session *handle, int *error);
struct janus_plugin_result *janus_echotest_handle_message(janus_plugin_session *handle, char *transaction, char *message, char *sdp_type, char *sdp);
void janus_echotest_setup_media(janus_plugin_session *handle);
void janus_echotest_incoming_rtp(janus_plugin_session *handle, int video, char *buf, int len);
void janus_echotest_incoming_rtcp(janus_plugin_session *handle, int video, char *buf, int len);
void janus_echotest_incoming_data(janus_plugin_session *handle, char *buf, int len);
void janus_echotest_slow_link(janus_plugin_session *handle, int uplink, int video);
void janus_echotest_hangup_media(janus_plugin_session *handle);
void janus_echotest_destroy_session(janus_plugin_session *handle, int *error);
char* janus_echotest_query_session(janus_plugin_session *handle);
void janus_echotest_get_vp8info(char * offset,int len,janus_vp8_infos * infos); 
static void * janus_echotest_postprocess(void * data);

#if defined(__ppc__) || defined(__ppc64__)
	# define swap2(d)  \
	((d&0x000000ff)<<8) |  \
	((d&0x0000ff00)>>8)
#else
	# define swap2(d) d
#endif

#define LIBAVCODEC_VER_AT_LEAST(major, minor) \
	(LIBAVCODEC_VERSION_MAJOR > major || \
	 (LIBAVCODEC_VERSION_MAJOR == major && \
	  LIBAVCODEC_VERSION_MINOR >= minor))





/* Plugin setup */
static janus_plugin janus_echotest_plugin =
	JANUS_PLUGIN_INIT (
		.init = janus_echotest_init,
		.destroy = janus_echotest_destroy,

		.get_api_compatibility = janus_echotest_get_api_compatibility,
		.get_version = janus_echotest_get_version,
		.get_version_string = janus_echotest_get_version_string,
		.get_description = janus_echotest_get_description,
		.get_name = janus_echotest_get_name,
		.get_author = janus_echotest_get_author,
		.get_package = janus_echotest_get_package,
		
		.create_session = janus_echotest_create_session,
		.handle_message = janus_echotest_handle_message,
		.setup_media = janus_echotest_setup_media,
		.incoming_rtp = janus_echotest_incoming_rtp,
		.incoming_rtcp = janus_echotest_incoming_rtcp,
		.incoming_data = janus_echotest_incoming_data,
		.slow_link = janus_echotest_slow_link,
		.hangup_media = janus_echotest_hangup_media,
		.destroy_session = janus_echotest_destroy_session,
		.query_session = janus_echotest_query_session,
	);

/* Plugin creator */
janus_plugin *create(void) {
	JANUS_LOG(LOG_VERB, "%s created!\n", JANUS_ECHOTEST_NAME);
	return &janus_echotest_plugin;
}


/* Useful stuff */
static volatile gint initialized = 0, stopping = 0;
static janus_callbacks *gateway = NULL;
static GThread *handler_thread;
static GThread *watchdog;
static GThread *pp_thread;
static void *janus_echotest_handler(void *data);

typedef struct janus_echotest_message {
	janus_plugin_session *handle;
	char *transaction;
	char *message;
	char *sdp_type;
	char *sdp;
} janus_echotest_message;
static GAsyncQueue *messages = NULL;
static janus_echotest_message exit_message;

typedef struct janus_echotest_session {
	janus_plugin_session *handle;
	janus_echotest_incoming_pp* pp_data;
	gboolean has_audio;
	gboolean has_video;
	gboolean has_data;
	gboolean audio_active;
	gboolean video_active;
	uint64_t bitrate;
	janus_recorder *arc;	/* The Janus recorder instance for this user's audio, if enabled */
	janus_recorder *vrc;	/* The Janus recorder instance for this user's video, if enabled */
	janus_recorder *drc;	/* The Janus recorder instance for this user's data, if enabled */
	janus_mutex rec_mutex;	/* Mutex to protect the recorders from race conditions */
	guint16 slowlink_count;
	volatile gint hangingup;
	gint64 destroyed;	/* Time at which this session was marked as destroyed */
} janus_echotest_session;
static GHashTable *sessions;
static GList *old_sessions;
static janus_mutex sessions_mutex;

static void janus_echotest_message_free(janus_echotest_message *msg) {
	if(!msg || msg == &exit_message)
		return;

	msg->handle = NULL;

	g_free(msg->transaction);
	msg->transaction = NULL;
	g_free(msg->message);
	msg->message = NULL;
	g_free(msg->sdp_type);
	msg->sdp_type = NULL;
	g_free(msg->sdp);
	msg->sdp = NULL;

	g_free(msg);
}


/* Error codes */
#define JANUS_ECHOTEST_ERROR_NO_MESSAGE			411
#define JANUS_ECHOTEST_ERROR_INVALID_JSON		412
#define JANUS_ECHOTEST_ERROR_INVALID_ELEMENT	413


/* EchoTest watchdog/garbage collector (sort of) */
void *janus_echotest_watchdog(void *data);
void *janus_echotest_watchdog(void *data) {
	JANUS_LOG(LOG_INFO, "EchoTest watchdog started\n");
	gint64 now = 0;
	while(g_atomic_int_get(&initialized) && !g_atomic_int_get(&stopping)) {
		janus_mutex_lock(&sessions_mutex);
		/* Iterate on all the sessions */
		now = janus_get_monotonic_time();
		if(old_sessions != NULL) {
			GList *sl = old_sessions;
			JANUS_LOG(LOG_HUGE, "Checking %d old EchoTest sessions...\n", g_list_length(old_sessions));
			while(sl) {
				janus_echotest_session *session = (janus_echotest_session *)sl->data;
				if(!session) {
					sl = sl->next;
					continue;
				}
				if(now-session->destroyed >= 5*G_USEC_PER_SEC) {
					/* We're lazy and actually get rid of the stuff only after a few seconds */
					JANUS_LOG(LOG_VERB, "Freeing old EchoTest session\n");
					GList *rm = sl->next;
					old_sessions = g_list_delete_link(old_sessions, sl);
					sl = rm;
					session->handle = NULL;
					g_free(session);
					session = NULL;
					continue;
				}
				sl = sl->next;
			}
		}
		janus_mutex_unlock(&sessions_mutex);
		g_usleep(500000);
	}
	JANUS_LOG(LOG_INFO, "EchoTest watchdog stopped\n");
	return NULL;
}


/* Plugin implementation */
int janus_echotest_init(janus_callbacks *callback, const char *config_path) {
	if(g_atomic_int_get(&stopping)) {
		/* Still stopping from before */
		return -1;
	}
	if(callback == NULL || config_path == NULL) {
		/* Invalid arguments */
		return -1;
	}

	/* Read configuration */
	char filename[255];
	g_snprintf(filename, 255, "%s/%s.cfg", config_path, JANUS_ECHOTEST_PACKAGE);
	JANUS_LOG(LOG_VERB, "Configuration file: %s\n", filename);
	janus_config *config = janus_config_parse(filename);
	if(config != NULL)
		janus_config_print(config);
	/* This plugin actually has nothing to configure... */
	janus_config_destroy(config);
	config = NULL;
	
	sessions = g_hash_table_new(NULL, NULL);
	janus_mutex_init(&sessions_mutex);
	messages = g_async_queue_new_full((GDestroyNotify) janus_echotest_message_free);
	/* This is the callback we'll need to invoke to contact the gateway */
	gateway = callback;
	g_atomic_int_set(&initialized, 1);

	GError *error = NULL;
	/* Start the sessions watchdog */
	watchdog = g_thread_try_new("echotest watchdog", &janus_echotest_watchdog, NULL, &error);
	if(error != NULL) {
		g_atomic_int_set(&initialized, 0);
		JANUS_LOG(LOG_ERR, "Got error %d (%s) trying to launch the EchoTest watchdog thread...\n", error->code, error->message ? error->message : "??");
		return -1;
	}
	/* Launch the thread that will handle incoming messages */
	handler_thread = g_thread_try_new("echotest handler", janus_echotest_handler, NULL, &error);
	if(error != NULL) {
		g_atomic_int_set(&initialized, 0);
		JANUS_LOG(LOG_ERR, "Got error %d (%s) trying to launch the EchoTest handler thread...\n", error->code, error->message ? error->message : "??");
		return -1;
	}
	pp_publishers = g_hash_table_new(NULL, NULL);
	janus_mutex_init(&pp_publishers_mutex); 
	JANUS_LOG(LOG_INFO, "%s initialized!\n", JANUS_ECHOTEST_NAME);
	return 0;
}

void janus_echotest_destroy(void) {
	if(!g_atomic_int_get(&initialized))
		return;
	g_atomic_int_set(&stopping, 1);

	g_async_queue_push(messages, &exit_message);
	if(handler_thread != NULL) {
		g_thread_join(handler_thread);
		handler_thread = NULL;
	}
	if(watchdog != NULL) {
		g_thread_join(watchdog);
		watchdog = NULL;
	}

	/* FIXME We should destroy the sessions cleanly */
	janus_mutex_lock(&sessions_mutex);
	g_hash_table_destroy(sessions);
	janus_mutex_unlock(&sessions_mutex);
	g_async_queue_unref(messages);
	messages = NULL;
	sessions = NULL;

	g_atomic_int_set(&initialized, 0);
	g_atomic_int_set(&stopping, 0);
	JANUS_LOG(LOG_INFO, "%s destroyed!\n", JANUS_ECHOTEST_NAME);
}

int janus_echotest_get_api_compatibility(void) {
	/* Important! This is what your plugin MUST always return: don't lie here or bad things will happen */
	return JANUS_PLUGIN_API_VERSION;
}

int janus_echotest_get_version(void) {
	return JANUS_ECHOTEST_VERSION;
}

const char *janus_echotest_get_version_string(void) {
	return JANUS_ECHOTEST_VERSION_STRING;
}

const char *janus_echotest_get_description(void) {
	return JANUS_ECHOTEST_DESCRIPTION;
}

const char *janus_echotest_get_name(void) {
	return JANUS_ECHOTEST_NAME;
}

const char *janus_echotest_get_author(void) {
	return JANUS_ECHOTEST_AUTHOR;
}

const char *janus_echotest_get_package(void) {
	return JANUS_ECHOTEST_PACKAGE;
}

void janus_echotest_create_session(janus_plugin_session *handle, int *error) {
	if(g_atomic_int_get(&stopping) || !g_atomic_int_get(&initialized)) {
		*error = -1;
		return;
	}	
	janus_echotest_session *session = (janus_echotest_session *)g_malloc0(sizeof(janus_echotest_session));
	if(session == NULL) {
		JANUS_LOG(LOG_FATAL, "Memory error!\n");
		*error = -2;
		return;
	}
	session->handle = handle;
	session->has_audio = FALSE;
	session->has_video = FALSE;
	session->has_data = FALSE;
	session->audio_active = TRUE;
	session->video_active = TRUE;
	janus_mutex_init(&session->rec_mutex);
	session->bitrate = 0;	/* No limit */
	session->destroyed = 0;

	session->pp_data = malloc(sizeof(janus_echotest_incoming_pp));
	session->pp_data->data = NULL;
	janus_mutex_init(&session->pp_data->mutex);
	pp_thread = g_thread_new("postprocess thread", &janus_echotest_postprocess,session->pp_data);


	g_atomic_int_set(&session->hangingup, 0);
	handle->plugin_handle = session;
	janus_mutex_lock(&sessions_mutex);
	g_hash_table_insert(sessions, handle, session);
	janus_mutex_unlock(&sessions_mutex);

	return;
}

void janus_echotest_destroy_session(janus_plugin_session *handle, int *error) {
	if(g_atomic_int_get(&stopping) || !g_atomic_int_get(&initialized)) {
		*error = -1;
		return;
	}	
	janus_echotest_session *session = (janus_echotest_session *)handle->plugin_handle;
	if(!session) {
		JANUS_LOG(LOG_ERR, "No session associated with this handle...\n");
		*error = -2;
		return;
	}
	JANUS_LOG(LOG_VERB, "Removing Echo Test session...\n");
	janus_mutex_lock(&sessions_mutex);
	if(!session->destroyed) {
		session->destroyed = janus_get_monotonic_time();
		g_hash_table_remove(sessions, handle);
		/* Cleaning up and removing the session is done in a lazy way */
		old_sessions = g_list_append(old_sessions, session);
	}

	g_list_free(session->pp_data);
	janus_mutex_unlock(&sessions_mutex);
	return;
}

char *janus_echotest_query_session(janus_plugin_session *handle) {
	if(g_atomic_int_get(&stopping) || !g_atomic_int_get(&initialized)) {
		return NULL;
	}	
	janus_echotest_session *session = (janus_echotest_session *)handle->plugin_handle;
	if(!session) {
		JANUS_LOG(LOG_ERR, "No session associated with this handle...\n");
		return NULL;
	}
	/* In the echo test, every session is the same: we just provide some configure info */
	json_t *info = json_object();
	json_object_set_new(info, "audio_active", json_string(session->audio_active ? "true" : "false"));
	json_object_set_new(info, "video_active", json_string(session->video_active ? "true" : "false"));
	json_object_set_new(info, "bitrate", json_integer(session->bitrate));
	if(session->arc || session->vrc || session->drc) {
		json_t *recording = json_object();
		if(session->arc && session->arc->filename)
			json_object_set_new(recording, "audio", json_string(session->arc->filename));
		if(session->vrc && session->vrc->filename)
			json_object_set_new(recording, "video", json_string(session->vrc->filename));
		if(session->drc && session->drc->filename)
			json_object_set_new(recording, "data", json_string(session->drc->filename));
		json_object_set_new(info, "recording", recording);
	}
	json_object_set_new(info, "slowlink_count", json_integer(session->slowlink_count));
	json_object_set_new(info, "destroyed", json_integer(session->destroyed));
	char *info_text = json_dumps(info, JSON_INDENT(3) | JSON_PRESERVE_ORDER);
	json_decref(info);
	return info_text;
}

struct janus_plugin_result *janus_echotest_handle_message(janus_plugin_session *handle, char *transaction, char *message, char *sdp_type, char *sdp) {
	if(g_atomic_int_get(&stopping) || !g_atomic_int_get(&initialized))
		return janus_plugin_result_new(JANUS_PLUGIN_ERROR, g_atomic_int_get(&stopping) ? "Shutting down" : "Plugin not initialized");
	janus_echotest_message *msg = g_malloc0(sizeof(janus_echotest_message));
	if(msg == NULL) {
		JANUS_LOG(LOG_FATAL, "Memory error!\n");
		return janus_plugin_result_new(JANUS_PLUGIN_ERROR, "Memory error");
	}
	msg->handle = handle;
	msg->transaction = transaction;
	msg->message = message;
	msg->sdp_type = sdp_type;
	msg->sdp = sdp;
	g_async_queue_push(messages, msg);

	/* All the requests to this plugin are handled asynchronously */
	return janus_plugin_result_new(JANUS_PLUGIN_OK_WAIT, "I'm taking my time!");
}

void janus_echotest_setup_media(janus_plugin_session *handle) {
	JANUS_LOG(LOG_INFO, "WebRTC media is now available\n");
	if(g_atomic_int_get(&stopping) || !g_atomic_int_get(&initialized))
		return;
	janus_echotest_session *session = (janus_echotest_session *)handle->plugin_handle;	
	if(!session) {
		JANUS_LOG(LOG_ERR, "No session associated with this handle...\n");
		return;
	}
	if(session->destroyed)
		return;
	g_atomic_int_set(&session->hangingup, 0);
	/* We really don't care, as we only send RTP/RTCP we get in the first place back anyway */
}

void janus_echotest_incoming_rtp(janus_plugin_session *handle, int video, char *buf, int len) {
	if(handle == NULL || handle->stopped || g_atomic_int_get(&stopping) || !g_atomic_int_get(&initialized))
		return;
	/* Simple echo test */
	if(gateway) {
		/* Honour the audio/video active flags */
		janus_echotest_session *session = (janus_echotest_session *)handle->plugin_handle;	
		if(!session) {
			JANUS_LOG(LOG_ERR, "No session associated with this handle...\n");
			return;
		}
		if(session->destroyed)
			return;
		if((!video && session->audio_active) || (video && session->video_active)) {
			janus_echotest_incoming_pp * entry = session->pp_data;

			janus_mutex_lock(&entry->mutex); 
			unsigned char * vp8_h = (unsigned char *)(buf+19) ;
			if(entry->need_keyframe  &&  !((vp8_h[0] == 0x9D) && (vp8_h[1] == 0x01) && (vp8_h[2] == 0x2A)))
			{
				JANUS_LOG(LOG_VERB, "Sending FIR/PLI for post process\n");
			
				char rtcpbuf[24];
				memset(rtcpbuf, 0, 24);
				janus_rtcp_fir((char *)&rtcpbuf, 20, &entry->fir_seq);
				
				gateway->relay_rtcp(handle, video, rtcpbuf, 20);
				/* Send a PLI too, just in case... */
				memset(rtcpbuf, 0, 12);
				janus_rtcp_pli((char *)&rtcpbuf, 12);

				gateway->relay_rtcp(handle, video, rtcpbuf, 12);
				entry->need_keyframe = 0; 			
			}
			else
			{
				janus_echotest_rtp_packet * rtp_packet = g_malloc0(sizeof(janus_echotest_rtp_packet)); 
				rtp_packet->len = len; 
				rtp_packet->data = g_malloc0(len); 
				memcpy(rtp_packet->data,buf,len); 
				entry->data = g_list_append(entry->data,rtp_packet); 
				// Fixme g_list_append will enumerate all member of the list in order to add the item at the end -> we should save the last item somewhere and use 
				// the g_list_insert instead of append. 		 
			}
			janus_mutex_unlock(&entry->mutex); 
			/* Send the frame back */
			gateway->relay_rtp(handle, video, buf, len);
		}
	}
}

void janus_echotest_incoming_rtcp(janus_plugin_session *handle, int video, char *buf, int len) {
	if(handle == NULL || handle->stopped || g_atomic_int_get(&stopping) || !g_atomic_int_get(&initialized))
		return;
	/* Simple echo test */
	if(gateway) {
		janus_echotest_session *session = (janus_echotest_session *)handle->plugin_handle;	
		if(!session) {
			JANUS_LOG(LOG_ERR, "No session associated with this handle...\n");
			return;
		}
		if(session->destroyed)
			return;
		if(session->bitrate > 0)
			janus_rtcp_cap_remb(buf, len, session->bitrate);
		gateway->relay_rtcp(handle, video, buf, len);
	}
}

void janus_echotest_incoming_data(janus_plugin_session *handle, char *buf, int len) {
	if(handle == NULL || handle->stopped || g_atomic_int_get(&stopping) || !g_atomic_int_get(&initialized))
		return;
	/* Simple echo test */
	if(gateway) {
		janus_echotest_session *session = (janus_echotest_session *)handle->plugin_handle;	
		if(!session) {
			JANUS_LOG(LOG_ERR, "No session associated with this handle...\n");
			return;
		}
		if(session->destroyed)
			return;
		if(buf == NULL || len <= 0)
			return;
		char *text = g_malloc0(len+1);
		memcpy(text, buf, len);
		*(text+len) = '\0';
		JANUS_LOG(LOG_VERB, "Got a DataChannel message (%zu bytes) to bounce back: %s\n", strlen(text), text);
		/* We send back the same text with a custom prefix */
		const char *prefix = "Janus EchoTest here! You wrote: ";
		char *reply = g_malloc0(strlen(prefix)+len+1);
		g_snprintf(reply, strlen(prefix)+len+1, "%s%s", prefix, text);
		g_free(text);
		gateway->relay_data(handle, reply, strlen(reply));
		g_free(reply);
	}
}

void janus_echotest_slow_link(janus_plugin_session *handle, int uplink, int video) {
	/* The core is informing us that our peer got or sent too many NACKs, are we pushing media too hard? */
	if(handle == NULL || handle->stopped || g_atomic_int_get(&stopping) || !g_atomic_int_get(&initialized))
		return;
	janus_echotest_session *session = (janus_echotest_session *)handle->plugin_handle;	
	if(!session) {
		JANUS_LOG(LOG_ERR, "No session associated with this handle...\n");
		return;
	}
	if(session->destroyed)
		return;
	session->slowlink_count++;
	if(uplink && !video && !session->audio_active) {
		/* We're not relaying audio and the peer is expecting it, so NACKs are normal */
		JANUS_LOG(LOG_VERB, "Getting a lot of NACKs (slow uplink) for audio, but that's expected, a configure disabled the audio forwarding\n");
	} else if(uplink && video && !session->video_active) {
		/* We're not relaying video and the peer is expecting it, so NACKs are normal */
		JANUS_LOG(LOG_VERB, "Getting a lot of NACKs (slow uplink) for video, but that's expected, a configure disabled the video forwarding\n");
	} else {
		/* Slow uplink or downlink, maybe we set the bitrate cap too high? */
		if(video) {
			/* Halve the bitrate, but don't go too low... */
			session->bitrate = session->bitrate > 0 ? session->bitrate : 512*1024;
			session->bitrate = session->bitrate/2;
			if(session->bitrate < 64*1024)
				session->bitrate = 64*1024;
			JANUS_LOG(LOG_WARN, "Getting a lot of NACKs (slow %s) for %s, forcing a lower REMB: %"SCNu64"\n",
				uplink ? "uplink" : "downlink", video ? "video" : "audio", session->bitrate);
			/* ... and send a new REMB back */
			char rtcpbuf[24];
			janus_rtcp_remb((char *)(&rtcpbuf), 24, session->bitrate);
			gateway->relay_rtcp(handle, 1, rtcpbuf, 24);
			/* As a last thing, notify the user about this */
			json_t *event = json_object();
			json_object_set_new(event, "echotest", json_string("event"));
			json_t *result = json_object();
			json_object_set_new(result, "status", json_string("slow_link"));
			json_object_set_new(result, "bitrate", json_integer(session->bitrate));
			json_object_set_new(event, "result", result);
			char *event_text = json_dumps(event, JSON_INDENT(3) | JSON_PRESERVE_ORDER);
			json_decref(event);
			event = NULL;
			gateway->push_event(session->handle, &janus_echotest_plugin, NULL, event_text, NULL, NULL);
			g_free(event_text);
		}
	}
}

void janus_echotest_hangup_media(janus_plugin_session *handle) {
	JANUS_LOG(LOG_INFO, "No WebRTC media anymore\n");
	if(g_atomic_int_get(&stopping) || !g_atomic_int_get(&initialized))
		return;
	janus_echotest_session *session = (janus_echotest_session *)handle->plugin_handle;
	if(!session) {
		JANUS_LOG(LOG_ERR, "No session associated with this handle...\n");
		return;
	}
	if(session->destroyed)
		return;
	if(g_atomic_int_add(&session->hangingup, 1))
		return;
	/* Send an event to the browser and tell it's over */
	json_t *event = json_object();
	json_object_set_new(event, "echotest", json_string("event"));
	json_object_set_new(event, "result", json_string("done"));
	char *event_text = json_dumps(event, JSON_INDENT(3) | JSON_PRESERVE_ORDER);
	json_decref(event);
	JANUS_LOG(LOG_VERB, "Pushing event: %s\n", event_text);
	int ret = gateway->push_event(handle, &janus_echotest_plugin, NULL, event_text, NULL, NULL);
	JANUS_LOG(LOG_VERB, "  >> %d (%s)\n", ret, janus_get_api_error(ret));
	g_free(event_text);
	/* Get rid of the recorders, if available */
	janus_mutex_lock(&session->rec_mutex);
	if(session->arc) {
		janus_recorder_close(session->arc);
		JANUS_LOG(LOG_INFO, "Closed audio recording %s\n", session->arc->filename ? session->arc->filename : "??");
		janus_recorder_free(session->arc);
	}
	session->arc = NULL;
	if(session->vrc) {
		janus_recorder_close(session->vrc);
		JANUS_LOG(LOG_INFO, "Closed video recording %s\n", session->vrc->filename ? session->vrc->filename : "??");
		janus_recorder_free(session->vrc);
	}
	session->vrc = NULL;
	if(session->drc) {
		janus_recorder_close(session->drc);
		JANUS_LOG(LOG_INFO, "Closed data recording %s\n", session->drc->filename ? session->drc->filename : "??");
		janus_recorder_free(session->drc);
	}
	session->drc = NULL;
	janus_mutex_unlock(&session->rec_mutex);
	/* Reset controls */
	session->has_audio = FALSE;
	session->has_video = FALSE;
	session->has_data = FALSE;
	session->audio_active = TRUE;
	session->video_active = TRUE;
	session->bitrate = 0;
}

/* Thread to handle incoming messages */
static void *janus_echotest_handler(void *data) {
	JANUS_LOG(LOG_VERB, "Joining EchoTest handler thread\n");
	janus_echotest_message *msg = NULL;
	int error_code = 0;
	char *error_cause = g_malloc0(512);
	if(error_cause == NULL) {
		JANUS_LOG(LOG_FATAL, "Memory error!\n");
		return NULL;
	}
	json_t *root = NULL;
	while(g_atomic_int_get(&initialized) && !g_atomic_int_get(&stopping)) {
		msg = g_async_queue_pop(messages);
		if(msg == NULL)
			continue;
		if(msg == &exit_message)
			break;
		if(msg->handle == NULL) {
			janus_echotest_message_free(msg);
			continue;
		}
		janus_echotest_session *session = NULL;
		janus_mutex_lock(&sessions_mutex);
		if(g_hash_table_lookup(sessions, msg->handle) != NULL ) {
			session = (janus_echotest_session *)msg->handle->plugin_handle;
		}
		janus_mutex_unlock(&sessions_mutex);
		if(!session) {
			JANUS_LOG(LOG_ERR, "No session associated with this handle...\n");
			janus_echotest_message_free(msg);
			continue;
		}
		if(session->destroyed) {
			janus_echotest_message_free(msg);
			continue;
		}
		/* Handle request */
		error_code = 0;
		root = NULL;
		JANUS_LOG(LOG_VERB, "Handling message: %s\n", msg->message);
		if(msg->message == NULL) {
			JANUS_LOG(LOG_ERR, "No message??\n");
			error_code = JANUS_ECHOTEST_ERROR_NO_MESSAGE;
			g_snprintf(error_cause, 512, "%s", "No message??");
			goto error;
		}
		json_error_t error;
		root = json_loads(msg->message, 0, &error);
		if(!root) {
			JANUS_LOG(LOG_ERR, "JSON error: on line %d: %s\n", error.line, error.text);
			error_code = JANUS_ECHOTEST_ERROR_INVALID_JSON;
			g_snprintf(error_cause, 512, "JSON error: on line %d: %s", error.line, error.text);
			goto error;
		}
		if(!json_is_object(root)) {
			JANUS_LOG(LOG_ERR, "JSON error: not an object\n");
			error_code = JANUS_ECHOTEST_ERROR_INVALID_JSON;
			g_snprintf(error_cause, 512, "JSON error: not an object");
			goto error;
		}
		/* Parse request */
		json_t *audio = json_object_get(root, "audio");
		if(audio && !json_is_boolean(audio)) {
			JANUS_LOG(LOG_ERR, "Invalid element (audio should be a boolean)\n");
			error_code = JANUS_ECHOTEST_ERROR_INVALID_ELEMENT;
			g_snprintf(error_cause, 512, "Invalid value (audio should be a boolean)");
			goto error;
		}
		json_t *video = json_object_get(root, "video");
		if(video && !json_is_boolean(video)) {
			JANUS_LOG(LOG_ERR, "Invalid element (video should be a boolean)\n");
			error_code = JANUS_ECHOTEST_ERROR_INVALID_ELEMENT;
			g_snprintf(error_cause, 512, "Invalid value (video should be a boolean)");
			goto error;
		}
		json_t *bitrate = json_object_get(root, "bitrate");
		if(bitrate && (!json_is_integer(bitrate) || json_integer_value(bitrate) < 0)) {
			JANUS_LOG(LOG_ERR, "Invalid element (bitrate should be a positive integer)\n");
			error_code = JANUS_ECHOTEST_ERROR_INVALID_ELEMENT;
			g_snprintf(error_cause, 512, "Invalid value (bitrate should be a positive integer)");
			goto error;
		}
		json_t *record = json_object_get(root, "record");
		if(record && !json_is_boolean(record)) {
			JANUS_LOG(LOG_ERR, "Invalid element (record should be a boolean)\n");
			error_code = JANUS_ECHOTEST_ERROR_INVALID_ELEMENT;
			g_snprintf(error_cause, 512, "Invalid value (record should be a boolean)");
			goto error;
		}
		json_t *recfile = json_object_get(root, "filename");
		if(recfile && !json_is_string(recfile)) {
			JANUS_LOG(LOG_ERR, "Invalid element (filename should be a string)\n");
			error_code = JANUS_ECHOTEST_ERROR_INVALID_ELEMENT;
			g_snprintf(error_cause, 512, "Invalid value (filename should be a string)");
			goto error;
		}
		/* Enforce request */
		if(audio) {
			session->audio_active = json_is_true(audio);
			JANUS_LOG(LOG_VERB, "Setting audio property: %s\n", session->audio_active ? "true" : "false");
		}
		if(video) {
			if(!session->video_active && json_is_true(video)) {
				/* Send a PLI */
				JANUS_LOG(LOG_VERB, "Just (re-)enabled video, sending a PLI to recover it\n");
				char buf[12];
				memset(buf, 0, 12);
				janus_rtcp_pli((char *)&buf, 12);
				gateway->relay_rtcp(session->handle, 1, buf, 12);
			}
			session->video_active = json_is_true(video);
			JANUS_LOG(LOG_VERB, "Setting video property: %s\n", session->video_active ? "true" : "false");
		}
		if(bitrate) {
			session->bitrate = json_integer_value(bitrate);
			JANUS_LOG(LOG_VERB, "Setting video bitrate: %"SCNu64"\n", session->bitrate);
			if(session->bitrate > 0) {
				/* FIXME Generate a new REMB (especially useful for Firefox, which doesn't send any we can cap later) */
				char buf[24];
				memset(buf, 0, 24);
				janus_rtcp_remb((char *)&buf, 24, session->bitrate);
				JANUS_LOG(LOG_VERB, "Sending REMB\n");
				gateway->relay_rtcp(session->handle, 1, buf, 24);
				/* FIXME How should we handle a subsequent "no limit" bitrate? */
			}
		}
		/* Any SDP to handle? */
		if(msg->sdp) {
			JANUS_LOG(LOG_VERB, "This is involving a negotiation (%s) as well:\n%s\n", msg->sdp_type, msg->sdp);
			session->has_audio = (strstr(msg->sdp, "m=audio") != NULL);
			session->has_video = (strstr(msg->sdp, "m=video") != NULL);
			session->has_data = (strstr(msg->sdp, "DTLS/SCTP") != NULL);
		}

		if(!audio && !video && !bitrate && !record && !msg->sdp) {
			JANUS_LOG(LOG_ERR, "No supported attributes (audio, video, bitrate, record, jsep) found\n");
			error_code = JANUS_ECHOTEST_ERROR_INVALID_ELEMENT;
			g_snprintf(error_cause, 512, "Message error: no supported attributes (audio, video, bitrate, record, jsep) found");
			goto error;
		}

		json_decref(root);
		/* Prepare JSON event */
		json_t *event = json_object();
		json_object_set_new(event, "echotest", json_string("event"));
		json_object_set_new(event, "result", json_string("ok"));
		char *event_text = json_dumps(event, JSON_INDENT(3) | JSON_PRESERVE_ORDER);
		json_decref(event);
		JANUS_LOG(LOG_VERB, "Pushing event: %s\n", event_text);
		if(!msg->sdp) {
			int ret = gateway->push_event(msg->handle, &janus_echotest_plugin, msg->transaction, event_text, NULL, NULL);
			JANUS_LOG(LOG_VERB, "  >> %d (%s)\n", ret, janus_get_api_error(ret));
		} else {
			/* Forward the same offer to the gateway, to start the echo test */
			const char *type = NULL;
			if(!strcasecmp(msg->sdp_type, "offer"))
				type = "answer";
			if(!strcasecmp(msg->sdp_type, "answer"))
				type = "offer";
			/* Any media direction that needs to be fixed? */
			char *sdp = g_strdup(msg->sdp);
			if(strstr(sdp, "a=recvonly")) {
				/* Turn recvonly to inactive, as we simply bounce media back */
				sdp = janus_string_replace(sdp, "a=recvonly", "a=inactive");
			} else if(strstr(sdp, "a=sendonly")) {
				/* Turn sendonly to recvonly */
				sdp = janus_string_replace(sdp, "a=sendonly", "a=recvonly");
				/* FIXME We should also actually not echo this media back, though... */
			}
			/* Make also sure we get rid of ULPfec, red, etc. */
			if(strstr(sdp, "ulpfec")) {
				/* FIXME This really needs some better code */
				sdp = janus_string_replace(sdp, "a=rtpmap:116 red/90000\r\n", "");
				sdp = janus_string_replace(sdp, "a=rtpmap:117 ulpfec/90000\r\n", "");
				sdp = janus_string_replace(sdp, "a=rtpmap:96 rtx/90000\r\n", "");
				sdp = janus_string_replace(sdp, "a=fmtp:96 apt=100\r\n", "");
				sdp = janus_string_replace(sdp, "a=rtpmap:97 rtx/90000\r\n", "");
				sdp = janus_string_replace(sdp, "a=fmtp:97 apt=101\r\n", "");
				sdp = janus_string_replace(sdp, "a=rtpmap:98 rtx/90000\r\n", "");
				sdp = janus_string_replace(sdp, "a=fmtp:98 apt=116\r\n", "");
				sdp = janus_string_replace(sdp, " 116", "");
				sdp = janus_string_replace(sdp, " 117", "");
				sdp = janus_string_replace(sdp, " 96", "");
				sdp = janus_string_replace(sdp, " 97", "");
				sdp = janus_string_replace(sdp, " 98", "");
			}
			/* How long will the gateway take to push the event? */
			g_atomic_int_set(&session->hangingup, 0);
			gint64 start = janus_get_monotonic_time();
			int res = gateway->push_event(msg->handle, &janus_echotest_plugin, msg->transaction, event_text, type, sdp);
			JANUS_LOG(LOG_VERB, "  >> Pushing event: %d (took %"SCNu64" us)\n",
				res, janus_get_monotonic_time()-start);
			g_free(sdp);
		}
		g_free(event_text);
		janus_echotest_message_free(msg);
		continue;
		
error:
		{
			if(root != NULL)
				json_decref(root);
			/* Prepare JSON error event */
			json_t *event = json_object();
			json_object_set_new(event, "echotest", json_string("event"));
			json_object_set_new(event, "error_code", json_integer(error_code));
			json_object_set_new(event, "error", json_string(error_cause));
			char *event_text = json_dumps(event, JSON_INDENT(3) | JSON_PRESERVE_ORDER);
			json_decref(event);
			JANUS_LOG(LOG_VERB, "Pushing event: %s\n", event_text);
			int ret = gateway->push_event(msg->handle, &janus_echotest_plugin, msg->transaction, event_text, NULL, NULL);
			JANUS_LOG(LOG_VERB, "  >> %d (%s)\n", ret, janus_get_api_error(ret));
			g_free(event_text);
			janus_echotest_message_free(msg);
		}
	}
	g_free(error_cause);
	JANUS_LOG(LOG_VERB, "Leaving EchoTest handler thread\n");
	return NULL;
}
void janus_echotest_get_vp8info(char * offset,int len,janus_vp8_infos * infos)
{
		uint8_t * buf_ptr = (uint8_t *) offset; 
			
		infos->key = 0; 
		infos->xbit = 0; 
		infos->sbit = 0; 
		
		uint8_t vp8pd = * buf_ptr;
		
		len--;
		buf_ptr++;
		
		uint8_t xbit = infos->xbit = (vp8pd & 0x80);
		uint8_t sbit = infos->sbit = (vp8pd & 0x10);
		infos->pid = (vp8pd & 0x07); 
		
		if(xbit) 
		{
			len--;

			vp8pd = * buf_ptr;
			uint8_t ibit = (vp8pd & 0x80);
			uint8_t lbit = (vp8pd & 0x40);
			uint8_t tbit = (vp8pd & 0x20);
			uint8_t kbit = (vp8pd & 0x10);
		
			if(ibit) 
			{
				buf_ptr++;
				len--;
				vp8pd = * buf_ptr;
				uint8_t mbit = (vp8pd & 0x80);
				if(mbit) 
				{
					buf_ptr++;
					len--;
				}
			}
			if(lbit) 
			{
				buf_ptr++;
				len--;
				vp8pd = * buf_ptr;
			}
			if(tbit || kbit) 
			{
				buf_ptr++; 
				len--;
			}
			buf_ptr++;	/* Now we're in the payload */
			
			if(sbit) 
			{
				unsigned long int vp8ph = 0;
				memcpy(&vp8ph, buf_ptr, 4);
				vp8ph = ntohl(vp8ph);
				uint8_t pbit = ((vp8ph & 0x01000000) >> 24);
				if(!pbit) 
				{
					/* Get resolution */
					unsigned char *c = (unsigned char * )(buf_ptr + 3);
					/* vet via sync code */
					if(c[0]!=0x9d||c[1]!=0x01||c[2]!=0x2a) 
						JANUS_LOG(LOG_WARN, "First 3-bytes after header not what they're supposed to be?\n");
					else 
					{
						infos->vp8w = swap2(*(unsigned short*)(c+3))&0x3fff;
						infos->vp8ws = swap2(*(unsigned short*)(c+3))>>14;
						infos->vp8h = swap2(*(unsigned short*)(c+5))&0x3fff;
						infos->vp8hs = swap2(*(unsigned short*)(c+5))>>14;
						infos->key = 1; 
					}
				}
			}
		}
		infos->len = len; 
		infos->offset = (char *) buf_ptr;  
}
static void * janus_echotest_postprocess(void * data)
{
				
	GList * start; 
	GList * tmp; 
	int first_frame = 0; 
	janus_echotest_incoming_pp * userdata = (janus_echotest_incoming_pp * ) data; 
	int key_frame = 0; 
	int was_key_frame = 0; 
	int cur_seq_number = 0; 
	
	int nb_search = 0, key_search = 0,reset_search_min_seq = 0, broken = 0; 
	int numBytes = 1024 * 768 * 3;	/* FIXME */
	uint8_t * received_frame = g_malloc0(numBytes);
	janus_vp8_infos * infos = g_malloc0(sizeof(janus_vp8_infos));
	unsigned char * compFrame = g_malloc0(numBytes);
	unsigned char * myFrame = g_malloc0(numBytes);
	userdata->need_keyframe = 0; 
	
	int frame_len = 0; 
	int vp8w  = 0;
	int vp8ws = 0;
	int vp8h  = 0;
	int vp8hs = 0;
	
	int complete_frame = 0; 
	int reinit_decoder = 1; 
	
	AVFrame * m_pFrame = NULL, * sws_frame = NULL, * my_frame = NULL; 
	av_register_all();
	avcodec_register_all();
	avformat_network_init(); 
	
	AVCodecContext * m_pCodecCtx = NULL;
	AVCodec * m_pCodec;
	AVCodec * o_pCodec  =  avcodec_find_encoder(AV_CODEC_ID_VP8);
	AVStream *vStream;
	
	// to output with RTP
	
	AVOutputFormat * o_fmt = av_guess_format("rtp", NULL, NULL); 
	AVCodecContext * o_cod_ctx = avcodec_alloc_context3(o_pCodec);
	
	avcodec_get_context_defaults3(o_cod_ctx, AVMEDIA_TYPE_VIDEO);
	AVFormatContext * o_fmt_ctx = avformat_alloc_context();
	
	o_fmt_ctx->oformat = o_fmt; 
	AVDictionary *opts = NULL;
		
	vStream = avformat_new_stream(o_fmt_ctx,o_pCodec); 
	avcodec_get_context_defaults3(vStream->codec, AVMEDIA_TYPE_VIDEO);
	
	vStream->codec->codec_id = AV_CODEC_ID_VP8;
	vStream->codec->codec_type = AVMEDIA_TYPE_VIDEO;
	vStream->codec->time_base = (AVRational){1, 30};
	vStream->codec->width = 640;
	vStream->codec->height = 480;
	vStream->codec->pix_fmt = AV_PIX_FMT_YUV420P;
	vStream->codec->bit_rate = 256000; 
	vStream->codec->slices       = 8;
	//vStream->codec->profile      = 3;
	vStream->codec->thread_count = 1;
	vStream->codec->keyint_min   = 100;
	vStream->codec->rc_min_rate = 128000; 
	vStream->codec->rc_max_rate = 384000; 
	//vStream->codec->qmin = 4;
	//vStream->codec->qmax = 56;
	av_dict_set(&opts, "sync_lookahead", "0", 0);
	av_dict_set(&opts, "rc_lookahead", "0", 0);
	av_dict_set(&opts, "quality", "realtime", 0);
	av_dict_set(&opts, "deadline", "realtime", 0);
	//av_dict_set(&opts, "max-intra-rate", "90", 0);
	av_dict_set(&opts, "error_resilient", "er", 0);
	  
	if (o_fmt_ctx->flags & AVFMT_GLOBALHEADER) 
		vStream->codec->flags |= CODEC_FLAG_GLOBAL_HEADER;
	
	sprintf(o_fmt_ctx->filename,"rtp://127.0.0.1:5000"); 
	
	avcodec_open2(vStream->codec,o_pCodec,&opts);
	avio_open(&o_fmt_ctx->pb,o_fmt_ctx->filename, AVIO_FLAG_WRITE); 
	avformat_write_header(o_fmt_ctx, NULL);
		
	char sdp[2048]; 
	av_sdp_create	(&o_fmt_ctx,1,sdp,2047); 
	JANUS_LOG(LOG_INFO, "[postprocess] sdp : %s\n",sdp);
   	
   	char header_buf[16]; 
	
	// scaler 
	struct SwsContext * resize = NULL;
	struct SwsContext * myResize = NULL; 			
	
	int rtp_written = 0; 
	int sframe_search = 0;
	janus_mutex_lock(&userdata->mutex); 
	tmp = g_list_first(userdata->data );
	janus_mutex_unlock(&userdata->mutex);   
	unsigned long waiting = 0; 
	int alive = 1; 
	
	while(!g_atomic_int_get(&stopping) && alive)
	{
		janus_mutex_lock(&userdata->mutex); 
		start = g_list_first(userdata->data );
		janus_mutex_unlock(&userdata->mutex);   
		key_frame = 0; 
		
		if(!start) // Empty packet list -> wait 
		{
			usleep(2000); 
			waiting++; 
			continue; 
		}
		
		if(first_frame && tmp) goto process_frame; 
		
		if(!tmp && (key_search > 120) )
		{
			// ask the main thread to send FIR/PLI -> need a key frame. 
			janus_mutex_lock(&userdata->mutex); 
			userdata->need_keyframe = 1; 
			janus_mutex_unlock(&userdata->mutex); 
			key_search = 0; 
			usleep(25000); 
			//JANUS_LOG(LOG_ERR, "Waiting for the first key frame !!! \n");
		}
		
		if (tmp) 
		{
			janus_echotest_rtp_packet * rtp_packet = (janus_echotest_rtp_packet * ) tmp->data; 
			unsigned char * vp8_h = (unsigned char * )(rtp_packet->data) + 19;	
			if((vp8_h[0] == 0x9D) && (vp8_h[1] == 0x01) && (vp8_h[2] == 0x2A))
			{
				JANUS_LOG(LOG_INFO, "[postprocess] YEAH First key frame OK \n");
				first_frame = 1;
				key_search = 0; 
				key_frame = 1; 
				goto process_frame;  
			}
			key_search++;
			goto delete_and_continue; 
		}
		
		janus_mutex_lock(&userdata->mutex); 
		tmp = g_list_first(userdata->data );
		janus_mutex_unlock(&userdata->mutex); 
		
				
		continue; 
		
	delete_and_continue :	
		
		janus_mutex_lock(&userdata->mutex); 
		GList * delete = tmp; 
		janus_echotest_rtp_packet * delete_rtp = (janus_echotest_rtp_packet * ) delete->data;
		g_free (delete_rtp->data);	
		g_free (delete->data);
		tmp = tmp->next; 			
		userdata->data  = start = g_list_remove_link (start, delete);
		g_list_free (delete);
		janus_mutex_unlock(&userdata->mutex); 
		continue; 

	ccontinue : 		// useless, just to catch something (stats) with undeleted packets in a previous version of this code 
		
		continue;
		
	process_frame : 
		; // label followed by declaration, not a statement so it wont compile without that empty statement. 
		
		janus_echotest_rtp_packet * rtp_packet = (janus_echotest_rtp_packet * ) tmp->data; 		
		int skip = 0; 
		memcpy(header_buf,rtp_packet->data,16);  
		janus_pp_rtp_header * rtp = (janus_pp_rtp_header *) header_buf;
		if(rtp->extension) 
		{
			janus_pp_rtp_header_extension *ext = (janus_pp_rtp_header_extension *)(header_buf+12);
			skip = 4 + ntohs(ext->length)*4;
		}
		
		char * offset = rtp_packet->data+12+skip;
		int len = rtp_packet->len-12-skip; 
		
		if(key_frame)	// In the case we were searching a key_frame 
		{
			cur_seq_number = ntohs(rtp->seq_number)-1; 
			was_key_frame = 1; 
			JANUS_LOG(LOG_INFO, "[postprocess] Key frame received setting current sequence to :%"SCNu16" \n",ntohs(rtp->seq_number)-1);
		}
				
		// handle reset
		if (((cur_seq_number - ntohs(rtp->seq_number) > 10000)) && tmp)
		{
			//reset
			//JANUS_LOG(LOG_ERR, "RESET in RTP seq_number current : %"SCNu32" packet %"SCNu16"\n",cur_seq_number,ntohs(rtp->seq_number) );
			reset_search_min_seq = 1; 
			cur_seq_number = ntohs(rtp->seq_number); 
			goto ccontinue; 		
		}
		if(reset_search_min_seq)
		{
			if (ntohs(rtp->seq_number) < cur_seq_number )
			{
				//JANUS_LOG(LOG_ERR, "RESET min seq found  %"SCNu16"\n",ntohs(rtp->seq_number));
				cur_seq_number = ntohs(rtp->seq_number);
			}
			janus_mutex_lock(&userdata->mutex); 
			tmp = tmp->next; 
			janus_mutex_unlock(&userdata->mutex); 
			if(!tmp) // end of min seq number search 
			{
				reset_search_min_seq = 0;
				cur_seq_number--;  
				//JANUS_LOG(LOG_ERR, "RESET end of min seq search\n"); 
			} 
			goto ccontinue;			
		}
		//// end handle reset
		
		if(ntohs(rtp->seq_number) != (cur_seq_number+1))
		{	  
			// Packet not folowing 
			if(ntohs(rtp->seq_number) < cur_seq_number)
				goto delete_and_continue; 
				
			nb_search++; 
			janus_mutex_lock(&userdata->mutex); 
			tmp = tmp->next;
			janus_mutex_unlock(&userdata->mutex); 
			if(!tmp && (nb_search > 100))
			{
			// will arrive too late, skip
				JANUS_LOG(LOG_VERB, "[postprocess] packet too late -> skip \n");
				cur_seq_number++;
				tmp = start; 
				frame_len = 0; 
				nb_search = 0;
				was_key_frame = 0;  
				goto ccontinue; 
			}
			goto ccontinue; 
		}
		else
		{
			// packet is the next one 
		
			cur_seq_number = ntohs(rtp->seq_number); 
			nb_search = 0; 
			
			janus_echotest_get_vp8info(offset,len,infos); 
	
			if(infos->key)
				was_key_frame = 1; 
			
			if(sframe_search > 20) // FIXME : the good number 
			{
				JANUS_LOG(LOG_VERB, "sframe_search > 20 ...0_o \n");
				was_key_frame = 0; 
				sframe_search = 0; 
				first_frame = 0; 
				goto delete_and_continue; 
			}
			if(frame_len == 0 && !infos->sbit) 
			{
				JANUS_LOG(LOG_VERB, "frame_len = 0 and !infos->sbit 0_o \n");
				sframe_search ++; 
				goto delete_and_continue; 	
			}
			
			if(infos->sbit && !infos->pid)
				frame_len = 0; 
		
			if((vp8w*vp8h+vp8ws*vp8hs) != ((infos->vp8w*infos->vp8h+infos->vp8ws*infos->vp8hs)))
			{
				vp8w  = infos->vp8w;
				vp8ws = infos->vp8ws;
				vp8h  = infos->vp8h;
				vp8hs = infos->vp8hs;	
				reinit_decoder = 1; 
				JANUS_LOG(LOG_VERB, "[POSTPROCESS] resolution has changed !!!!!!!!! %d %d\n",vp8w,vp8h);			
			}
			
			memcpy(received_frame+frame_len,infos->offset,infos->len); 
			frame_len += infos->len; 
			
			if(!rtp->markerbit) // incomplete frame, continue.  
				goto delete_and_continue;
			
			
			// here, the frame is complete 
			
			memcpy(received_frame+frame_len,"00000000000000000000000000000000",32); // add padding for ffmpeg 
			
			AVPacket vpacket;
			av_init_packet(&vpacket);
			vpacket.stream_index = 0; 
			vpacket.data = received_frame;
			vpacket.size = frame_len;
			vpacket.dts = (rtp->timestamp)/90;
			vpacket.pts = (rtp->timestamp)/90;
			
			if(was_key_frame)
				vpacket.flags |= AV_PKT_FLAG_KEY; 
			
			was_key_frame = 0; 
			
			if(reinit_decoder)
			{
				// i'm not sure that is needed. Maybe with older version of libav. 
				// As the resolution change trigger a keyframe, the decoder should work. 
				// the scaler need the original resolution too line 2817
				
				m_pCodec = avcodec_find_decoder(AV_CODEC_ID_VP8);	
				m_pCodecCtx = avcodec_alloc_context3(m_pCodec);
				m_pCodecCtx->codec_id = AV_CODEC_ID_VP8;
		
				#if LIBAVCODEC_VER_AT_LEAST(53, 21)
					avcodec_get_context_defaults3(m_pCodecCtx, AVMEDIA_TYPE_VIDEO);
				#else
					avcodec_get_context_defaults2(m_pCodecCtx, AVMEDIA_TYPE_VIDEO);
				#endif				
				m_pCodecCtx->codec_type = AVMEDIA_TYPE_VIDEO;
				m_pCodecCtx->time_base = (AVRational){1, 60};
				m_pCodecCtx->width = vp8w;
				m_pCodecCtx->height = vp8h; 
				m_pCodecCtx->pix_fmt = AV_PIX_FMT_YUV420P;
				m_pCodecCtx->flags |= CODEC_FLAG_GLOBAL_HEADER;
				
				avcodec_open2(m_pCodecCtx,m_pCodec,0);
				if(!m_pFrame)
					m_pFrame = av_frame_alloc()	;
				if(!sws_frame)
					sws_frame = av_frame_alloc();
				if(!my_frame)
					my_frame = av_frame_alloc();
					 
				resize = sws_getContext(640,480, PIX_FMT_RGB24, 640, 480, AV_PIX_FMT_YUV420P, SWS_BICUBIC, NULL, NULL, NULL);
				myResize = sws_getContext(vp8w,vp8h, AV_PIX_FMT_YUV420P, 640, 480, PIX_FMT_RGB24, SWS_BICUBIC, NULL, NULL, NULL); 
				reinit_decoder = 0; 
			}
			
			int framefinished = 0;
			int nres = avcodec_decode_video2(m_pCodecCtx,m_pFrame,&framefinished,&vpacket);
			av_free_packet(&vpacket); 
			
	check_decode_process : 
	
			if(nres < 0 )
			{
				JANUS_LOG(LOG_ERR, "Decoder BROKEN ->> !!! \n");
				// decoder is broken, 
				broken++; 
				// if 5 new frame without result, request key_frame
				if(broken > 5 )
				{
					first_frame = 0; 
					reinit_decoder = 1; 
				}
				frame_len = 0; 
				goto delete_and_continue; 
			}
			
			if((nres == frame_len) && (!framefinished) && rtp->markerbit)
			{
				// with some codecs of libav version, you need to give decode_video2 a null packet in order to get the frame 
				// call decode_video2 with empty packet in respect to AV_CODEC_CAP_DELAY
				AVPacket packet;
				av_init_packet(&packet);
				packet.stream_index = 0; 
				packet.data = NULL;
				packet.size = 0;
				nres = avcodec_decode_video2(m_pCodecCtx,m_pFrame,&framefinished,&packet);	
				av_free_packet(&packet); 
				goto check_decode_process; 
			}
			
			broken = 0; 
			
			if(!framefinished)
				goto delete_and_continue; 
			
			
			// complete frame decoded -> rescale 
			avpicture_fill((AVPicture*) my_frame, myFrame, PIX_FMT_RGB24, 640, 480);
			sws_frame->format = PIX_FMT_RGB24; 
			sws_frame->height = 640; 
			sws_frame->width = 480; 			 
			avpicture_fill((AVPicture*) sws_frame, compFrame, AV_PIX_FMT_YUV420P, 640, 480);
			sws_frame->format = AV_PIX_FMT_YUV420P; 
			sws_frame->height = 640; 
			sws_frame->width = 480; 
			sws_scale(myResize, (const uint8_t *const *)(m_pFrame->data), m_pFrame->linesize, 0, vp8h, my_frame->data, my_frame->linesize);
			
			// HERE YOU HAVE YOUR RAW FRAME,  
			// If you need it in another format like RGB24, scale it first to RGB, then rescale it to YUV420P
			
			// ... here make your frame manipulation, opencv ...  
			sws_scale(resize, (const uint8_t *const *)(my_frame->data), my_frame->linesize, 0, vp8h, sws_frame->data, sws_frame->linesize);
			// we encode it ...
		encode_frame : 
			complete_frame++; 
			AVPacket opacket;
			av_init_packet(&opacket);
			int decode_finished = 0,enc_finished = 0; 
			if (o_fmt_ctx->oformat->flags & AVFMT_GLOBALHEADER) vStream->codec->flags |= CODEC_FLAG_GLOBAL_HEADER;
			
			
			av_free_packet(&opacket); // weired but without that, encode_video bug/crash ! // yes, it is weired.
			
			decode_finished = avcodec_encode_video2(vStream->codec,&opacket,sws_frame,&enc_finished); 
			opacket.stream_index = 0; 

			if(enc_finished)
			{
				/* write the compressed frame in the media file ->RTP  */
				opacket.dts = opacket.pts = AV_NOPTS_VALUE; 
				//	if(vStream->codec->coded_frame->key_frame) opacket.flags |= AV_PKT_FLAG_KEY; -> deprecated 
				int write_ret = av_write_frame(o_fmt_ctx, &opacket);
				if (write_ret < 0) 
					JANUS_LOG(LOG_ERR,"Error writing frame to RTP\n");
				else
					rtp_written += opacket.size;			
			}
			else if(decode_finished < 0 )
				JANUS_LOG(LOG_ERR, "[postprocess] ENCoder BROKEN ->> !!! \n");		
			av_free_packet(&opacket);
		
			frame_len = 0; 			
			goto delete_and_continue; 
		}		 
	}
	
	janus_mutex_lock(&userdata->mutex);
	g_list_free(userdata->data); 
	janus_mutex_unlock(&userdata->mutex); 
	janus_mutex_destroy(&userdata->mutex); 
	g_free(userdata); 
	g_free(compFrame);
	g_free(myFrame);
	g_free(received_frame); 
	g_free(infos); 
	JANUS_LOG(LOG_INFO, "Leaving POSTPROCESS thread	\n");
	
	return NULL;
	 
}
