$(function() {
    opts = {
        delay: 20,
        geocoder_types: 'street_address,route,intersection,political,country,administrative_area_level_1,administrative_area_level_2,administrative_area_level_3,colloquial_area,locality,sublocality,neighborhood,premise,subpremise,postal_code,natural_feature,airport,park,street_number,point_of_interest',
        geocoder_address: true,
        maptype: 'normal'
    }
    $('#location').geo_autocomplete(opts); 
    $('#meeting_place').geo_autocomplete(opts); 
});