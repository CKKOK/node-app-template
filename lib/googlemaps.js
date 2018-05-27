const config = require('../config');

const googleMapsClient = require('@google/maps').createClient({
	key: config.apikeys.googleMaps,
	Promise: Promise
});

function calculateRouteDistance(route) {
	return new Promise(function(resolve, reject) {
		googleMapsClient
			.directions({
				origin: route.origin,
				destination: route.destination,
				waypoints: route.waypoints,
				mode: route.mode
			})
			.asPromise()
			.then(function(response) {
				let legs = response.json.routes[0].legs;
				let result = legs.reduce((acc, cur) => {
					return acc + cur.distance.value;
				}, 0);
				resolve(result / 1000);
			})
			.catch(function(error) {
				reject(error);
			});
	});
}

async function newRouteFromWaypointList(route) {
	let waypoints = [];
	let tmp = null;
	for (let pt in route) {
		tmp = pt.toString();
		if (route.hasOwnProperty(tmp)) {
			waypoints.push({
				lat: route[tmp].lat,
				lng: route[tmp].lng
			});
		}
	}
	var origin = waypoints.shift();
	var destination = waypoints.pop();
	let protoRoute = {
		origin: origin,
		destination: destination,
		waypoints: waypoints,
		mode: 'walking'
	};
	let distance = await calculateRouteDistance(protoRoute);
	let result = {
		type: 'run',
		origin: origin,
		destination: destination,
		waypoints: waypoints,
		distance: distance
	};
	return result;
}

module.exports = googleMapsClient;