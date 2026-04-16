"use client"

import { useMemo, useRef } from "react"
import { Canvas, useFrame } from "@react-three/fiber"
import { RoundedBox, ContactShadows, Environment, Lightformer } from "@react-three/drei"
import { EffectComposer, Bloom, Vignette, N8AO, SMAA, ToneMapping } from "@react-three/postprocessing"
import { ToneMappingMode } from "postprocessing"
import * as THREE from "three"

const ACCENT = "#8B5CF6"
const BG = "#060606"
const METAL = "#2b2733"
const WAX = "#3a2d5c"

const PERIOD = 5.0
const N = 5
const R = 0.52
const IMPACT = 2.8

// dock ring positions (ellipse for perspective)
function dockPos(i: number): [number, number, number] {
  const a = (i / N) * Math.PI * 2 + 0.35
  return [Math.cos(a) * R, -0.28, Math.sin(a) * R * 0.7]
}
function farPos(i: number): [number, number, number] {
  const a = (i / N) * Math.PI * 2 + 0.35
  return [Math.cos(a) * 2.6, 1.15, Math.sin(a) * 1.6]
}

const easeOutCubic = (p: number) => 1 - Math.pow(1 - p, 3)

// press head: 0 rest (up), 1 pressed (down)
function pressAmount(t: number): number {
  if (t < 2.5) return 0
  if (t < IMPACT) {
    const p = (t - 2.5) / 0.3
    return p * p * p // accelerate into impact
  }
  if (t < 2.96) {
    // recoil bounce
    return 1 - Math.sin(((t - IMPACT) / 0.16) * Math.PI) * 0.12
  }
  if (t < 3.2) return 1 // hold
  if (t < 3.7) return 1 - easeOutCubic((t - 3.2) / 0.5)
  return 0
}

// seal imprint glow
function sealGlow(t: number): number {
  if (t < IMPACT) return 0
  if (t < 3.0) return (t - IMPACT) / 0.2
  if (t < 4.6) return 1 - (t - 3.0) / 1.6
  return 0
}

function Press() {
  const head = useRef<THREE.Group>(null)
  const body = useRef<THREE.Group>(null)
  const chips = useRef<THREE.Group>(null)
  const sockets = useRef<THREE.Group>(null)
  const seal = useRef<THREE.Mesh>(null)
  const die = useRef<THREE.Mesh>(null)
  const emit = useRef<THREE.Group>(null)

  const docks = useMemo(() => Array.from({ length: N }, (_, i) => dockPos(i)), [])
  const fars = useMemo(() => Array.from({ length: N }, (_, i) => farPos(i)), [])

  useFrame((state) => {
    const t = state.clock.elapsedTime % PERIOD
    const press = pressAmount(t)
    const glow = sealGlow(t)

    if (head.current) head.current.position.y = 0.95 - press * 0.8

    // impact shake
    if (body.current) {
      const kick = t > IMPACT && t < IMPACT + 0.3 ? Math.sin((t - IMPACT) * 46) * 0.02 * (1 - (t - IMPACT) / 0.3) : 0
      body.current.position.y = kick
      body.current.rotation.z = kick * 0.4
    }

    if (seal.current) {
      const m = seal.current.material as THREE.MeshStandardMaterial
      m.emissiveIntensity = glow * 3.2
    }
    if (die.current) {
      const m = die.current.material as THREE.MeshStandardMaterial
      m.emissiveIntensity = 0.3 + glow * 1.6
    }

    // chips: fly in, dock, then consumed into press at impact
    if (chips.current) {
      chips.current.children.forEach((c, i) => {
        const dockStart = 0.3 + i * 0.36
        const dockDur = 0.7
        const mesh = c as THREE.Mesh
        const mat = mesh.material as THREE.MeshStandardMaterial
        if (t < dockStart) {
          mesh.scale.setScalar(0)
        } else if (t < dockStart + dockDur) {
          const p = easeOutCubic((t - dockStart) / dockDur)
          mesh.position.set(
            THREE.MathUtils.lerp(fars[i][0], docks[i][0], p),
            THREE.MathUtils.lerp(fars[i][1], docks[i][1], p),
            THREE.MathUtils.lerp(fars[i][2], docks[i][2], p)
          )
          mesh.rotation.y = (1 - p) * 6
          mesh.scale.setScalar(1)
          mat.opacity = Math.min(1, p * 2)
        } else if (t < IMPACT) {
          mesh.position.set(docks[i][0], docks[i][1], docks[i][2])
          mat.opacity = 1
        } else if (t < 3.18) {
          const p = (t - IMPACT) / 0.38
          mesh.position.set(
            THREE.MathUtils.lerp(docks[i][0], 0, p),
            THREE.MathUtils.lerp(docks[i][1], 0.55, p),
            THREE.MathUtils.lerp(docks[i][2], 0, p)
          )
          mesh.scale.setScalar(Math.max(0, 1 - p))
          mat.opacity = 1 - p
        } else {
          mesh.scale.setScalar(0)
        }
      })
    }

    // sockets glow when their chip is docked
    if (sockets.current) {
      sockets.current.children.forEach((s, i) => {
        const dockStart = 0.3 + i * 0.36
        const filled = t >= dockStart + 0.7 && t < IMPACT
        const m = (s as THREE.Mesh).material as THREE.MeshStandardMaterial
        m.emissiveIntensity = THREE.MathUtils.lerp(m.emissiveIntensity, filled ? 2.4 : 0.15, 0.2)
      })
    }

    // aggregated signature emitted: rises and drifts out, fading
    if (emit.current) {
      const visible = t >= IMPACT && t < 4.9
      emit.current.visible = visible
      if (visible) {
        const p = easeOutCubic((t - IMPACT) / 2.1)
        emit.current.position.set(0.0 + p * 0.7, -0.3 + p * 2.1, 0)
        emit.current.rotation.z = p * 2.4
        emit.current.scale.setScalar(0.5 + p * 0.7)
        emit.current.children.forEach((c) => {
          const m = (c as THREE.Mesh).material as THREE.MeshBasicMaterial
          m.opacity = (1 - p) * 0.95
        })
      }
    }
  })

  return (
    <group position={[2.3, -0.35, 0]} rotation={[0.05, -0.5, 0]} scale={1.1}>
      <group ref={body}>
        {/* base plate */}
        <RoundedBox args={[2.1, 0.32, 1.5]} radius={0.1} smoothness={5} position={[0, -0.62, 0]}>
          <meshStandardMaterial color={METAL} metalness={0.9} roughness={0.28} envMapIntensity={1.2} />
        </RoundedBox>
        {/* base trim glow */}
        <mesh position={[0, -0.47, 0.0]} rotation={[-Math.PI / 2, 0, 0]}>
          <ringGeometry args={[0.92, 0.99, 48]} />
          <meshBasicMaterial color={ACCENT} toneMapped={false} transparent opacity={0.5} side={THREE.DoubleSide} />
        </mesh>

        {/* guide rails */}
        {[-0.78, 0.78].map((x, i) => (
          <mesh key={i} position={[x, 0.5, -0.1]}>
            <cylinderGeometry args={[0.07, 0.07, 2.0, 20]} />
            <meshStandardMaterial color="#15131a" metalness={0.85} roughness={0.3} />
          </mesh>
        ))}
        {/* top cross bar */}
        <RoundedBox args={[1.85, 0.26, 0.55]} radius={0.09} smoothness={5} position={[0, 1.45, -0.1]}>
          <meshStandardMaterial color={METAL} metalness={0.88} roughness={0.3} />
        </RoundedBox>

        {/* wax pad / target */}
        <mesh position={[0, -0.4, 0]}>
          <cylinderGeometry args={[0.42, 0.46, 0.14, 36]} />
          <meshStandardMaterial color={WAX} metalness={0.2} roughness={0.55} />
        </mesh>
        {/* imprinted seal (glows on stamp) */}
        <mesh ref={seal} position={[0, -0.32, 0]}>
          <cylinderGeometry args={[0.34, 0.34, 0.05, 36]} />
          <meshStandardMaterial color={WAX} emissive={ACCENT} emissiveIntensity={0} metalness={0.3} roughness={0.4} />
        </mesh>

        {/* threshold sockets ring */}
        <group ref={sockets}>
          {docks.map((d, i) => (
            <mesh key={i} position={[d[0], -0.38, d[2]]} rotation={[Math.PI / 2, 0, 0]}>
              <torusGeometry args={[0.13, 0.025, 12, 24]} />
              <meshStandardMaterial color="#1a1722" emissive={ACCENT} emissiveIntensity={0.15} metalness={0.6} roughness={0.4} />
            </mesh>
          ))}
        </group>

        {/* signature key chips */}
        <group ref={chips}>
          {Array.from({ length: N }, (_, i) => (
            <mesh key={i}>
              <cylinderGeometry args={[0.15, 0.15, 0.09, 6]} />
              <meshStandardMaterial
                color={METAL}
                emissive={ACCENT}
                emissiveIntensity={0.6}
                metalness={0.85}
                roughness={0.25}
                transparent
                opacity={1}
              />
            </mesh>
          ))}
        </group>

        {/* press head */}
        <group ref={head} position={[0, 0.95, 0]}>
          <RoundedBox args={[1.05, 0.5, 0.85]} radius={0.12} smoothness={5} position={[0, 0.05, 0]}>
            <meshStandardMaterial color={METAL} metalness={0.92} roughness={0.2} envMapIntensity={1.3} />
          </RoundedBox>
          {/* knob */}
          <mesh position={[0, 0.45, 0]}>
            <cylinderGeometry args={[0.18, 0.22, 0.24, 28]} />
            <meshStandardMaterial color="#17151c" metalness={0.7} roughness={0.3} />
          </mesh>
          {/* accent band */}
          <mesh position={[0, 0.05, 0.431]}>
            <planeGeometry args={[0.7, 0.1]} />
            <meshBasicMaterial color={ACCENT} toneMapped={false} />
          </mesh>
          {/* die face */}
          <mesh ref={die} position={[0, -0.4, 0]}>
            <cylinderGeometry args={[0.3, 0.32, 0.18, 36]} />
            <meshStandardMaterial color="#0f0d14" emissive={ACCENT} emissiveIntensity={0.3} metalness={0.6} roughness={0.35} />
          </mesh>
        </group>

        {/* emitted aggregated signature */}
        <group ref={emit} visible={false} position={[0, -0.3, 0]}>
          <mesh rotation={[Math.PI / 2, 0, 0]}>
            <torusGeometry args={[0.26, 0.04, 16, 40]} />
            <meshBasicMaterial color={ACCENT} toneMapped={false} transparent opacity={0.9} />
          </mesh>
          <mesh>
            <torusGeometry args={[0.13, 0.03, 14, 32]} />
            <meshBasicMaterial color="#c9b3ff" toneMapped={false} transparent opacity={0.9} />
          </mesh>
        </group>
      </group>

      <ContactShadows position={[0, -0.78, 0]} opacity={0.55} scale={6} blur={2.6} far={2.5} color="#000000" />
    </group>
  )
}

function Dust() {
  const positions = useMemo(() => {
    const arr = new Float32Array(220 * 3)
    for (let i = 0; i < 220; i++) {
      arr[i * 3] = (Math.random() - 0.5) * 15
      arr[i * 3 + 1] = (Math.random() - 0.5) * 8
      arr[i * 3 + 2] = -2 - Math.random() * 6
    }
    return arr
  }, [])
  const ref = useRef<THREE.Points>(null)
  useFrame((state) => {
    if (ref.current) ref.current.rotation.z = state.clock.elapsedTime * 0.012
  })
  return (
    <points ref={ref}>
      <bufferGeometry>
        <bufferAttribute attach="attributes-position" args={[positions, 3]} />
      </bufferGeometry>
      <pointsMaterial color={ACCENT} size={0.022} transparent opacity={0.38} sizeAttenuation blending={THREE.AdditiveBlending} depthWrite={false} />
    </points>
  )
}

function Rig() {
  useFrame((state) => {
    const { camera, pointer } = state
    camera.position.x = THREE.MathUtils.lerp(camera.position.x, pointer.x * 0.45, 0.04)
    camera.position.y = THREE.MathUtils.lerp(camera.position.y, 0.3 + pointer.y * 0.25, 0.04)
    camera.lookAt(1.1, 0.1, 0)
  })
  return null
}

export default function HeroScene() {
  return (
    <div style={{ width: "100%", height: "100vh" }}>
      <Canvas
        camera={{ position: [0, 0.3, 5.4], fov: 46 }}
        gl={{ antialias: false, powerPreference: "high-performance", stencil: false }}
        dpr={[1, 2]}
        shadows
        onCreated={({ gl }) => { gl.toneMappingExposure = 1.1 }}
        style={{ background: BG }}
      >
        <fog attach="fog" args={[BG, 10, 18]} />
        <ambientLight intensity={0.25} />
        <directionalLight position={[4, 6, 4]} intensity={1.3} color="#f1ecff" castShadow shadow-mapSize={[2048, 2048]} shadow-bias={-0.0002} />
        <Press />
        <Dust />
        <Environment resolution={384}>
          <Lightformer intensity={2.4} position={[3, 3, 4]} scale={[4, 3, 1]} color="#f4f0ff" />
          <Lightformer intensity={1.4} position={[-4, 1, 3]} scale={[2, 4, 1]} color={ACCENT} />
          <Lightformer intensity={0.8} position={[0, 5, -3]} scale={[5, 2, 1]} color="#ffffff" />
          <Lightformer form="ring" intensity={1.5} position={[2, 0, 2]} scale={2.2} color="#b794ff" />
        </Environment>
        <Rig />
        <EffectComposer multisampling={0}>
          <N8AO aoRadius={0.5} intensity={2.2} distanceFalloff={0.8} quality="performance" />
          <Bloom intensity={0.55} luminanceThreshold={0.55} luminanceSmoothing={0.3} mipmapBlur />
          <ToneMapping mode={ToneMappingMode.ACES_FILMIC} />
          <Vignette eskil={false} offset={0.22} darkness={0.72} />
          <SMAA />
        </EffectComposer>
      </Canvas>
    </div>
  )
}