DAZN_MANIFEST_DAZNEDGE = {
    "video": {
        "video_288kbps": {
            "bitrate": 288,
            "width": 480,
            "height": 270,
            "framerate": 25,
        },
        "video_480kbps": {
            "bitrate": 480,
            "width": 640,
            "height": 360,
            "framerate": 25,
        },
        "video_840kbps": {
            "bitrate": 840,
            "width": 640,
            "height": 960,
            "framerate": 25,
        },
        "video_1500kbps": {
            "bitrate": 1500,
            "width": 960,
            "height": 540,
            "framerate": 25,
        },
        "video_2300kbps": {
            "bitrate": 2300,
            "width": 1280,
            "height": 720,
            "framerate": 25,
        },
        "video_3000kbps": {
            "bitrate": 3000,
            "width": 1280,
            "height": 720,
            "framerate": 25,
        },
        "video_4400kbps": {
            "bitrate": 4400,
            "width": 1280,
            "height": 720,
            "framerate": 50,
        },
        "video_6500kbps": {
            "bitrate": 6500,
            "width": 1280,
            "height": 720,
            "framerate": 50,
        },
        "video_8000kbps": {
            "bitrate": 8000,
            "width": 1920,
            "height": 1080,
            "framerate": 50,
        },
    },
    "audio": {
        "audio_64kbps": {"framerate": 48, "bitrate": 64},
        "audio_128kbps": {"framerate": 48, "bitrate": 128},
    },
}

DAZN_MANIFEST_AWS_AKAMAI = {
    "video": {
        "stream_video_1": {
            "bitrate": 8000,
            "width": 1280,
            "height": 720,
            "framerate": 50,
        },
        "stream_video_2": {
            "bitrate": 6500,
            "width": 1280,
            "height": 720,
            "framerate": 50,
        },
        "stream_video_3": {
            "bitrate": 4400,
            "width": 1280,
            "height": 720,
            "framerate": 50,
        },
        "stream_video_4": {
            "bitrate": 3000,
            "width": 1280,
            "height": 720,
            "framerate": 25,
        },
        "stream_video_5": {
            "bitrate": 2300,
            "width": 1280,
            "height": 720,
            "framerate": 25,
        },
        "stream_video_6": {
            "bitrate": 1500,
            "width": 960,
            "height": 540,
            "framerate": 25,
        },
        "stream_video_7": {
            "bitrate": 840,
            "width": 960,
            "height": 540,
            "framerate": 25,
        },
        "stream_video_8": {
            "bitrate": 480,
            "width": 960,
            "height": 540,
            "framerate": 25,
        },
        "stream_video_9": {
            "bitrate": 288,
            "width": 480,
            "height": 270,
            "framerate": 25,
        },
    },
    "audio": {
        "stream_audio_10_": {"framerate": 48, "bitrate": 65_604},
        "stream_audio_11_": {"framerate": 48, "bitrate": 128_058},
        "stream_audio_12_": {"framerate": 48, "bitrate": 128},
    },
}


TELEMETRY_SERVICES = {
    "analytics.google.com",
    "google-analytics.com",
    "doubleclick.net",
    "akamai.net",
    "scorecardresearch.com",
    "newrelic.com",
    "fullstory.com",
    "onetrust.com",
    "appsflyer.com",
    "pendo.io",
    "mixpanel.com",
    "segment.com",
    "hotjar.com",
    "clicktale.com",
    "crazyegg.com",
    "qualaroo.com",
    "intercom.com",
    "sentry.io",
    "conviva.com",
    "redditstatic.com",
    "nr-data.net",
    "reddit.com",
    "t.co",
    "twitter"
}

ROOT = "meta/temp/dazn"