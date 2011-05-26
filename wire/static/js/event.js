$(function() {
    $('article.message header .opts a').hide();
    $('article.message').hover(function() {
        $('header .opts a', this).show();
    }, function() {
        $('header .opts a', this).hide();
    })

    $('div.description').css('max-height', '75px');
    $('<p class="expander" expanded="no"><a href="#">&darr; Expand &darr;</a></p>').insertAfter('div.description');

    $('p.expander').click(function(e) {
        e.preventDefault();
        if($(this).attr('expanded') == 'yes'){
            $(this).prev().css('max-height', '75px');
            $(this).attr('expanded', 'no');
            $(this).html('<a href="#">&darr; Expand &darr;</a>');
        } else {
            $(this).prev().css('max-height', 'none');
            $(this).attr('expanded', 'yes');
            $(this).html('<a href="#">&uarr; Un-expand &uarr;</a>');

        }
    });

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
        zoom: 14,
        markers: mrkrs,
        maptype: G_PHYSICAL_MAP
    });

    $('article.event div.location div.map').hide();
    $('article.event div.location p a').click(function(e) {
        e.preventDefault();
        $('div.map', $(this).parent().parent()).toggle();
    });
});