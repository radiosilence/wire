$(function() {
    $('article.message header .opts a').hide();
    $('article.message').hover(function() {
        $('header .opts a', this).show();
    }, function() {
        $('header .opts a', this).hide();
    })

    mrkrs =  [
            {address: $('#map1').attr('address'),
                icon: {
                  image:              $('#map1').attr('marker_path')+'marker_event.png',
                  shadow:             false,
                  iconsize:           [108, 72],
                  shadowsize:         false,
                  iconanchor:         [10, 53],
                  infowindowanchor:   [14, 2]
                }
           }
        ];
    if ($("span#meeting-place").length > 0) {
        mrkrs[1] = {address: $('span#meeting-place').text(),
                icon: {
                  image:              $('#map1').attr('marker_path')+'marker_meet.png',
                  shadow:             false,
                  iconsize:           [111, 67],
                  shadowsize:         false,
                  iconanchor:         [15, 51],
                  infowindowanchor:   [14, 2]
            }};
    }
    $("#map1").gMap({
        zoom: 13,
        markers: mrkrs,
        maptype: G_HYBRID_MAP
    });

    $('article.event div.location div.map').hide();
    $('article.event div.location p a').click(function(e) {
        e.preventDefault();
        $('div.map', $(this).parent().parent()).toggle();
    });
});