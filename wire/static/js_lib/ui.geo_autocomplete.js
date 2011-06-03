/*
 * jQuery geo_autocomplete plugin 2.1.1
 *
 * Copyright (c) 2010 Bob Hitching
 *
 * Dual licensed under the MIT and GPL licenses:
 *   http://www.opensource.org/licenses/mit-license.php
 *   http://www.gnu.org/licenses/gpl.html
 *
 * Requires jQuery UI Autocomplete
 * 
 */
$.widget( "ui.geo_autocomplete", {
	// setup the element as an autocomplete widget with some geo goodness added
	_init: function() {
		this.options._geocoder = new google.maps.Geocoder; // geocoder object
		this.options._cache = {}; // cache of geocoder responses
		this.element.autocomplete(this.options);
		
		// _renderItem is used to prevent the widget framework from escaping the HTML required to show the static map thumbnail
		this.element.data('autocomplete')._renderItem = function(_ul, _item) {
			return $('<li></li>').data('item.autocomplete', _item).append(this.options.getItemHTML(_item)).appendTo(_ul);
		};
	},
	
	// default values
	options: {
		geocoder_region: '', // filter to a specific region, e.g. 'Europe'
		geocoder_types: 'locality,political,sublocality,neighborhood,country', // array of acceptable location types, see http://code.google.com/apis/maps/documentation/javascript/services.html#GeocodingAddressTypes
		geocoder_address: false, // true = use the full formatted address, false = use only the segment that matches the search term

		mapwidth: 100, // width of static map thumbnail
		mapheight: 100, // height of static map thumbnail
		maptype: 'terrain', // see http://code.google.com/apis/maps/documentation/staticmaps/#MapTypes
		mapsensor: false, // see http://code.google.com/apis/maps/documentation/staticmaps/#Sensor

		minLength: 3, // see http://jqueryui.com/demos/autocomplete/#option-minLength
		delay: 300, // see http://jqueryui.com/demos/autocomplete/#option-delay
		// callback function to get autocomplete results
		source: function(_request, _response) {
			if (_request.term in this.options._cache) {
				_response(this.options._cache[_request.term]);
			} else {
				var self = this;
				var _address = _request.term + (this.options.geocoder_region ? ', ' + this.options.geocoder_region : '');
				this.options._geocoder.geocode({'address': _address}, function(_results, _status) {
					var _parsed = [];
					if (_results && _status && _status == 'OK') {
						var _types = self.options.geocoder_types.split(',');
						$.each(_results, function(_key, _result) {
							// if this is an acceptable location type with a viewport, it's a good result
							if ($.map(_result.types, function(_type) {
								return $.inArray(_type, _types) != -1 ? _type : null;
							}).length && _result.geometry && _result.geometry.viewport) {

								if (self.options.geocoder_address) {
									_place = _result.formatted_address;
								} else {
									// place is first matching segment, or first segment
									var _place_parts = _result.formatted_address.split(',');
									var _place = _place_parts[0];
									$.each(_place_parts, function(_key, _part) {
										if (_part.toLowerCase().indexOf(_request.term.toLowerCase()) != -1) {
											_place = $.trim(_part);
											return false; // break
										}
									});
								}
							
								_parsed.push({
									value: _place,
									label: _result.formatted_address,
									viewport: _result.geometry.viewport
								});
							}
						});
					}
					self.options._cache[_request.term] = _parsed;
					_response(_parsed);
				});
			}
		},
		// returns the HTML used for each autocomplete list item
		getItemHTML: function(_item) {		
			var _src = 'http://maps.google.com/maps/api/staticmap?visible=' + _item.viewport.getSouthWest().toUrlValue() + '|' + _item.viewport.getNorthEast().toUrlValue() + '&size=' + this.mapwidth + 'x' + this.mapheight + '&maptype=' + this.maptype + '&sensor=' + (this.mapsensor ? 'true' : 'false');
			return '<a><img style="float:left;margin-right:5px;" src="' + _src + '" width="' + this.mapwidth + '" height="' + this.mapheight + '" /> ' + _item.label.replace(/,/gi, ',<br/>') + '<br clear="both" /></a>'
		}
	}
});