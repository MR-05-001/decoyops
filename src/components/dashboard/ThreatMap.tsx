import { useMemo } from 'react';
import DeckGL from '@deck.gl/react';
import { ScatterplotLayer, ArcLayer } from '@deck.gl/layers';
import Map from 'react-map-gl/maplibre';
import maplibregl from 'maplibre-gl';
import 'maplibre-gl/dist/maplibre-gl.css';
import type { Incident } from './IncidentFeed';

// Dark basemap style from Carto
const MAP_STYLE = 'https://basemaps.cartocdn.com/gl/dark-matter-nolabels-gl-style/style.json';

const INITIAL_VIEW_STATE = {
  longitude: 0,
  latitude: 20,
  zoom: 1,
  pitch: 30,
  bearing: 0
};

interface ThreatMapProps {
  incidents: Incident[];
  activeDecoysCount: number;
}

export function ThreatMap({ incidents, activeDecoysCount }: ThreatMapProps) {
  // Extract geolocated incidents
  const geoIncidents = useMemo(() => {
    return incidents.filter(i => i.geo_lat !== undefined && i.geo_lon !== undefined);
  }, [incidents]);

  const layers = [
    // Origin points
    new ScatterplotLayer({
      id: 'attack-origins',
      data: geoIncidents,
      getPosition: d => [d.geo_lon!, d.geo_lat!],
      getFillColor: d => d.status === 'CAPTURED' ? [255, 76, 76] : [245, 166, 35], // Red or Amber
      getRadius: 5,
      radiusUnits: 'pixels',
      opacity: 0.8,
      pickable: true,
    }),
    // Arcs to a generic "home" point (e.g. your server location, mocked here as NYC for visual effect)
    new ArcLayer({
      id: 'attack-arcs',
      data: geoIncidents,
      getSourcePosition: d => [d.geo_lon!, d.geo_lat!],
      getTargetPosition: _d => [-74.006, 40.7128], // New York (default target)
      getSourceColor: d => d.status === 'CAPTURED' ? [255, 76, 76, 120] : [245, 166, 35, 120],
      getTargetColor: _d => [100, 255, 218, 120], // dp-teal
      getWidth: 1.5,
    })
  ];

  return (
    <div className="relative w-full h-full bg-[#0a0a0b] overflow-hidden">
      <DeckGL
        initialViewState={INITIAL_VIEW_STATE}
        controller={true}
        layers={layers}
        getTooltip={({object}) => object && `${(object as Incident).sourceIp}\n${(object as Incident).vector}`}
      >
        <Map 
          mapLib={maplibregl} 
          mapStyle={MAP_STYLE} 
          attributionControl={false}
        />
      </DeckGL>

      {/* Overlay status */}
      <div className="absolute bottom-4 left-4 pointer-events-none">
        <div className="flex items-center gap-2 px-3 py-1.5 bg-black/60 border border-dp-line-soft backdrop-blur-sm rounded-sm">
          <div className={`w-2 h-2 rounded-full ${activeDecoysCount > 0 ? 'bg-dp-teal animate-pulse' : 'bg-dp-text-dim'}`} />
          <span className="font-mono text-[10px] text-dp-text-faint">
            {activeDecoysCount} active decoy{activeDecoysCount !== 1 ? 's' : ''} on radar
          </span>
        </div>
      </div>
    </div>
  );
}
