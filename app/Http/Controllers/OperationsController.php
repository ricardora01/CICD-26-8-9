<?php

namespace App\Http\Controllers;

use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Str;

class OperationsController extends Controller
{
    public function addition(int $a, int $b): int
    {
        return $a + $b;
    }

    public function generate(Request $request): JsonResponse
    {
        $validated = $request->validate([
            'length' => ['sometimes', 'integer', 'min:12', 'max:128'],
        ]);

        $length = $validated['length'] ?? 20;

        $password = Str::password(
            length: $length,
            letters: true,
            numbers: true,
            symbols: true,
            spaces: false
        );

        return response()->json([
            'success' => true,
            'password' => $password,
            'length' => strlen($password),
        ]);
    }
}


class URLanalyzerController extends Controller
{
    // Sufijos comunes de sitios maliciosos
    private const SUSPICIOUS_TLDS = [
        'tk', 'ml', 'ga', 'cf', 'gq', 'xyz', 'top', 'work',
        'click', 'link', 'country', 'download', 'stream', 'review',
    ];

    //Palabras comunes en links de phishing
    private const PHISHING_KEYWORDS = [
        'login', 'signin', 'verify', 'verification', 'secure',
        'account', 'update', 'confirm', 'password', 'banking',
        'wallet', 'recovery', 'unlock', 'suspend', 'alert',
    ];

    //Acortadores de links
    private const URL_SHORTENERS = [
        'bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly',
        'is.gd', 'buff.ly', 'rebrand.ly', 'cutt.ly', 'shorturl.at',
    ];
    
    public function analyze(Request $request): JsonResponse
    {
        // Se valida que el campo exista, sea un string y no tenga una longitud mayor a 2048
        $validated = $request->validate([
            'url' => ['required', 'string', 'max:2048'],
        ]);

        # Llamar la funcion InspectUrl con la URL que viene en el campo y asignarla a la variable report
        $report = $this->inspectUrl($validated['url']);

        # Asignar un estado HTTP segun el puntuaje del reporte, 422 no procesable y 200 para OK
        $status = match (true) {
            $report['score'] >= 60 => 422,
            $report['score'] >= 30 => 200,
            default                => 200,
        };

        # Se hace un JSON de respuesta en base a la funcion inspectURL
        return response()->json([
            'success'    => true,
            'url'        => $validated['url'],
            'risk_level' => $this->riskLevel($report['score']),
            'score'      => $report['score'],
            'is_malicious' => $report['score'] >= 60,
            'indicators' => $report['indicators'],
        ], $status);
    }

    public function inspectUrl(string $url): array
    {
        $indicators = [];
        $score = 0;

        // Descompone la URL en un arreglo para los valores scheme, host, path y query de la URL
        $parsed = parse_url($url);

        // Evita continuar la evaluacion si la URL no es valida o no esta definida
        if ($parsed === false || !isset($parsed['host']) || empty($parsed['scheme'])) {
            return [
                'score' => 100,
                'indicators' => ['URL inválida o sin esquema/host detectable'],
            ];
        }

        # Separar lo valores del arreglo "parsed" y los normaliza  minisculas
        $scheme = strtolower($parsed['scheme']);
        $host   = strtolower($parsed['host']);
        $path   = strtolower($parsed['path'] ?? '');
        $query  = strtolower($parsed['query'] ?? '');

        // Verificar si el protocolo HTTP no es seguro
        if ($scheme !== 'https') {
            $score += 15;
            $indicators[] = "Esquema no seguro: {$scheme}";
        }

        // Valida si el host en la URL es una IP
        if (filter_var($host, FILTER_VALIDATE_IP)) {
            $score += 35;
            $indicators[] = 'El host es una dirección IP';
        }

        // Cuenta los subdominios que hay al separar en cada punto con explode()
        $labels = explode('.', $host);
        if (count($labels) > 3) {
            $score += 20;
            $indicators[] = 'Exceso de subdominios (' . count($labels) . ')';
        }

        // Al revisar los subdominios, se checa el dominio final y se compara a la lista Suspicious_TLDS
        $tld = end($labels);
        if (in_array($tld, self::SUSPICIOUS_TLDS, true)) {
            $score += 25;
            $indicators[] = "TLD de alto riesgo: .{$tld}";
        }

        // Contar la cantidad de guiones que hay en el segmento de host para la URL
        if (substr_count($host, '-') >= 2) {
            $score += 15;
            $indicators[] = 'Uso excesivo de guiones en el host';
        }

        // Buscar el sufijo xn-- en el host, ya que indica que hay caracteres UNICODE subplantando a otros
        if (str_starts_with($host, 'xn--') || str_contains($host, 'xn--')) {
            $score += 30;
            $indicators[] = 'Dominio punycode)';
        }

        // Se concatena el path y query en una variable, separadas por un espacio para evitar falsos positivos
        $haystack = $path . ' ' . $query;
        // Buscar palabras de phishing en la variable concatenada (haystack)
        foreach (self::PHISHING_KEYWORDS as $kw) {
            if (str_contains($haystack, $kw)) {
                $score += 8;
                $indicators[] = "Palabra sensible en la ruta: '{$kw}'";
            }
        }

        // Encontrar si hay acortadores de URL enlistados
        if (in_array($host, self::URL_SHORTENERS, true)) {
            $score += 20;
            $indicators[] = 'Acortador de URL detectado';
        }

        // Comparar si hay un puerto en la URL, al no ser un puerto comun (80 o 443) se marca.
        if (isset($parsed['port']) && !in_array($parsed['port'], [80, 443], true)) {
            $score += 10;
            $indicators[] = "Puerto no estándar: {$parsed['port']}";
        }

        // Contar cantidad de parametros en la URL al separarlos, una gran cantidad puede ser sospechosa
        if ($query !== '') {
            $paramCount = substr_count($query, '&') + 1;
            if ($paramCount >= 6) {
                $score += 10;
                $indicators[] = "Exceso de parámetros en query ({$paramCount})";
            }
        }

        // Encontrar un simbolo @ antes del host en la URL
        if (str_contains($url, '@') && strpos($url, '@') < strpos($url, $host)) {
            $score += 25;
            $indicators[] = "Carácter '@' antes del host (enmascaramiento)";
        }

        // Para facilitar la interpretacion, el puntuaje se mantiene en una escala de 0-100
        // Se elije el menor valor entre 100 o el valor del diagnostico
        $score = min(100, $score);

        return [
            'score' => $score,
            'indicators' => $indicators,
        ];
    }

    // Funcion para indicar el nivel de riesgo en la URL.
    // match(true) evalua y devuelve el primer valor donde se cumpla la condicion 
    private function riskLevel(int $score): string
    {
        return match (true) {
            $score >= 60 => 'high',
            $score >= 30 => 'medium',
            $score > 0   => 'low',
            default      => 'undefined',
        };
    }
}
