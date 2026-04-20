"use client"

import { useMemo, useRef } from "react"
import { Canvas, useFrame } from "@react-three/fiber"
import { Environment, Lightformer } from "@react-three/drei"
import { EffectComposer, Bloom, ToneMapping, Vignette, SMAA } from "@react-three/postprocessing"
import { ToneMappingMode } from "postprocessing"
import * as THREE from "three"

const ACCENT = "#8B5CF6"
const ACCENT2 = "#6D5BD0"
const BG = "#060606"

const NOISE = /* glsl */ `
vec3 mod289(vec3 x){return x-floor(x*(1.0/289.0))*289.0;}
vec4 mod289(vec4 x){return x-floor(x*(1.0/289.0))*289.0;}
vec4 permute(vec4 x){return mod289(((x*34.0)+1.0)*x);}
vec4 taylorInvSqrt(vec4 r){return 1.79284291400159-0.85373472095314*r;}
float snoise(vec3 v){
  const vec2 C=vec2(1.0/6.0,1.0/3.0);const vec4 D=vec4(0.0,0.5,1.0,2.0);
  vec3 i=floor(v+dot(v,C.yyy));vec3 x0=v-i+dot(i,C.xxx);
  vec3 g=step(x0.yzx,x0.xyz);vec3 l=1.0-g;vec3 i1=min(g.xyz,l.zxy);vec3 i2=max(g.xyz,l.zxy);
  vec3 x1=x0-i1+C.xxx;vec3 x2=x0-i2+C.yyy;vec3 x3=x0-D.yyy;
  i=mod289(i);
  vec4 p=permute(permute(permute(i.z+vec4(0.0,i1.z,i2.z,1.0))+i.y+vec4(0.0,i1.y,i2.y,1.0))+i.x+vec4(0.0,i1.x,i2.x,1.0));
  float n_=0.142857142857;vec3 ns=n_*D.wyz-D.xzx;
  vec4 j=p-49.0*floor(p*ns.z*ns.z);vec4 x_=floor(j*ns.z);vec4 y_=floor(j-7.0*x_);
  vec4 x=x_*ns.x+ns.yyyy;vec4 y=y_*ns.x+ns.yyyy;vec4 h=1.0-abs(x)-abs(y);
  vec4 b0=vec4(x.xy,y.xy);vec4 b1=vec4(x.zw,y.zw);
  vec4 s0=floor(b0)*2.0+1.0;vec4 s1=floor(b1)*2.0+1.0;vec4 sh=-step(h,vec4(0.0));
  vec4 a0=b0.xzyw+s0.xzyw*sh.xxyy;vec4 a1=b1.xzyw+s1.xzyw*sh.zzww;
  vec3 p0=vec3(a0.xy,h.x);vec3 p1=vec3(a0.zw,h.y);vec3 p2=vec3(a1.xy,h.z);vec3 p3=vec3(a1.zw,h.w);
  vec4 norm=taylorInvSqrt(vec4(dot(p0,p0),dot(p1,p1),dot(p2,p2),dot(p3,p3)));
  p0*=norm.x;p1*=norm.y;p2*=norm.z;p3*=norm.w;
  vec4 m=max(0.6-vec4(dot(x0,x0),dot(x1,x1),dot(x2,x2),dot(x3,x3)),0.0);m=m*m;
  return 42.0*dot(m*m,vec4(dot(p0,x0),dot(p1,x1),dot(p2,x2),dot(p3,x3)));
}
float fbm(vec3 p){
  float f=0.0; float a=0.5;
  for(int i=0;i<4;i++){ f+=a*snoise(p); p*=2.02; a*=0.5; }
  return f;
}
`

{/* Vertical light pillars (god rays) standing as signers in the field */}
function LightPillars() {
  const pillars = useMemo(() => {
    const cfg: { x: number; z: number; h: number; w: number; phase: number; tone: number }[] = []
    const data = [
      [-5.2, -7, 0.0, 0.18],
      [-2.6, -4.5, 1.2, 0.55],
      [-0.4, -9, 2.1, 0.0],
      [1.8, -5.5, 3.4, 0.7],
      [4.4, -8, 0.8, 0.3],
      [-3.6, -11, 4.0, 0.9],
      [3.0, -12, 5.2, 0.15],
      [0.8, -3.8, 1.7, 0.45],
    ]
    for (const [x, z, phase, tone] of data) {
      cfg.push({ x, z, h: 16 + Math.abs(x) * 0.6, w: 0.9 + (1 - tone) * 0.4, phase, tone })
    }
    return cfg
  }, [])

  const refs = useRef<(THREE.ShaderMaterial | null)[]>([])
  useFrame((s) => {
    const t = s.clock.elapsedTime
    for (const m of refs.current) { if (m) m.uniforms.uTime.value = t }
  })

  return (
    <group position={[0, -1.5, 0]}>
      {pillars.map((p, i) => (
        <mesh key={i} position={[p.x, p.h * 0.5, p.z]}>
          <planeGeometry args={[p.w, p.h, 1, 1]} />
          <shaderMaterial
            ref={(r) => { refs.current[i] = r }}
            transparent
            depthWrite={false}
            side={THREE.DoubleSide}
            blending={THREE.AdditiveBlending}
            uniforms={{
              uTime: { value: 0 },
              uPhase: { value: p.phase },
              uTone: { value: p.tone },
              uA: { value: new THREE.Color(ACCENT) },
              uB: { value: new THREE.Color(ACCENT2) },
            }}
            vertexShader={`
              varying vec2 vUv;
              void main(){ vUv=uv; gl_Position=projectionMatrix*modelViewMatrix*vec4(position,1.0); }
            `}
            fragmentShader={NOISE + `
              uniform float uTime; uniform float uPhase; uniform float uTone;
              uniform vec3 uA; uniform vec3 uB; varying vec2 vUv;
              void main(){
                float cx=abs(vUv.x-0.5)*2.0;
                float core=smoothstep(1.0,0.0,cx);
                core=pow(core,2.2);
                float top=smoothstep(0.0,0.32,vUv.y);
                float bottom=smoothstep(1.0,0.6,vUv.y);
                float fall=top*bottom;
                float flick=0.72+0.28*sin(uTime*0.6+uPhase)*sin(uTime*0.23+uPhase*1.7);
                float gran=0.85+0.15*fbm(vec3(vUv*vec2(3.0,9.0),uTime*0.25+uPhase));
                vec3 col=mix(uA,uB,uTone*0.7+vUv.y*0.3);
                float a=core*fall*flick*gran*0.5;
                gl_FragColor=vec4(col,a);
              }
            `}
          />
        </mesh>
      ))}
    </group>
  )
}

{/* Volumetric fog slabs drifting through the pillars */}
function FogVolume() {
  const refs = useRef<(THREE.ShaderMaterial | null)[]>([])
  const layers = useMemo(() => [
    { z: -3, y: -1.4, scale: 26, op: 0.5, sp: 0.03, seed: 0.0 },
    { z: -6, y: -0.6, scale: 34, op: 0.42, sp: 0.022, seed: 11.0 },
    { z: -9.5, y: 0.4, scale: 44, op: 0.36, sp: 0.016, seed: 23.0 },
  ], [])
  useFrame((s) => {
    const t = s.clock.elapsedTime
    for (const m of refs.current) { if (m) m.uniforms.uTime.value = t }
  })
  return (
    <group>
      {layers.map((l, i) => (
        <mesh key={i} position={[0, l.y, l.z]}>
          <planeGeometry args={[l.scale, l.scale * 0.62, 1, 1]} />
          <shaderMaterial
            ref={(r) => { refs.current[i] = r }}
            transparent
            depthWrite={false}
            blending={THREE.AdditiveBlending}
            uniforms={{
              uTime: { value: 0 },
              uSeed: { value: l.seed },
              uSpeed: { value: l.sp },
              uOpacity: { value: l.op },
              uA: { value: new THREE.Color(ACCENT) },
              uB: { value: new THREE.Color(BG) },
            }}
            vertexShader={`
              varying vec2 vUv;
              void main(){ vUv=uv; gl_Position=projectionMatrix*modelViewMatrix*vec4(position,1.0); }
            `}
            fragmentShader={NOISE + `
              uniform float uTime; uniform float uSeed; uniform float uSpeed; uniform float uOpacity;
              uniform vec3 uA; uniform vec3 uB; varying vec2 vUv;
              void main(){
                vec2 p=vUv*3.2;
                float n=fbm(vec3(p.x+uTime*uSpeed, p.y-uTime*uSpeed*0.5, uSeed+uTime*0.04));
                n=n*0.5+0.5;
                float cloud=smoothstep(0.42,0.95,n);
                float edge=smoothstep(0.0,0.35,vUv.y)*smoothstep(1.0,0.55,vUv.y);
                float vign=smoothstep(0.0,0.3,vUv.x)*smoothstep(1.0,0.7,vUv.x);
                vec3 col=mix(uB,uA,cloud*0.65);
                float a=cloud*edge*vign*uOpacity;
                gl_FragColor=vec4(col,a);
              }
            `}
          />
        </mesh>
      ))}
    </group>
  )
}

{/* Floating dust caught in the light */}
function Dust() {
  const positions = useMemo(() => {
    const arr = new Float32Array(520 * 3)
    for (let i = 0; i < 520; i++) {
      arr[i * 3] = (Math.random() - 0.5) * 24
      arr[i * 3 + 1] = (Math.random() - 0.5) * 14
      arr[i * 3 + 2] = -Math.random() * 13
    }
    return arr
  }, [])
  const ref = useRef<THREE.Points>(null)
  useFrame((s) => {
    if (!ref.current) return
    const t = s.clock.elapsedTime
    ref.current.position.y = Math.sin(t * 0.12) * 0.4
    ref.current.rotation.y = t * 0.01
  })
  return (
    <points ref={ref}>
      <bufferGeometry>
        <bufferAttribute attach="attributes-position" args={[positions, 3]} />
      </bufferGeometry>
      <pointsMaterial color={ACCENT} size={0.03} transparent opacity={0.45} sizeAttenuation depthWrite={false} blending={THREE.AdditiveBlending} />
    </points>
  )
}

{/* Faint horizon glow disc behind the fog */}
function HorizonGlow() {
  return (
    <mesh position={[0, -0.5, -13]}>
      <circleGeometry args={[10, 48]} />
      <meshBasicMaterial color={ACCENT} transparent opacity={0.06} blending={THREE.AdditiveBlending} depthWrite={false} />
    </mesh>
  )
}

function Rig() {
  useFrame((s) => {
    s.camera.position.x = THREE.MathUtils.lerp(s.camera.position.x, s.pointer.x * 0.7, 0.03)
    s.camera.position.y = THREE.MathUtils.lerp(s.camera.position.y, 0.4 + s.pointer.y * 0.3, 0.03)
    s.camera.lookAt(0, 0.2, -7)
  })
  return null
}

export default function BgScene() {
  return (
    <Canvas
      camera={{ position: [0, 0.4, 6], fov: 62 }}
      gl={{ antialias: false, powerPreference: "high-performance", stencil: false }}
      dpr={[1, 1.75]}
      style={{ width: "100%", height: "100%", display: "block", background: BG }}
    >
      <fog attach="fog" args={[BG, 5, 19]} />
      <HorizonGlow />
      <FogVolume />
      <LightPillars />
      <Dust />
      <Environment resolution={256}>
        <Lightformer intensity={1.5} position={[2, 4, 3]} scale={[5, 6, 1]} color={ACCENT} />
        <Lightformer intensity={0.9} position={[-4, 2, 1]} scale={[3, 5, 1]} color={ACCENT2} />
        <Lightformer intensity={0.6} position={[0, -3, -6]} scale={[8, 2, 1]} color={ACCENT} />
      </Environment>
      <Rig />
      <EffectComposer multisampling={0}>
        <Bloom intensity={0.7} luminanceThreshold={0.3} luminanceSmoothing={0.4} mipmapBlur />
        <ToneMapping mode={ToneMappingMode.ACES_FILMIC} />
        <Vignette eskil={false} offset={0.2} darkness={0.75} />
        <SMAA />
      </EffectComposer>
    </Canvas>
  )
}