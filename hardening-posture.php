<?php
/**
 * Plugin Name: Hardening Posture (prototype)
 * Description: THROWAWAY SPIKE. Adds infrastructure hardening checks to Site Health and a "Hardening" tab with a deny-by-default posture and allow-list.
 * Version:     0.0.1-spike
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class HP_Prototype {

	const OPTION_POSTURE = 'hp_posture';
	const OPTION_STATES  = 'hp_states';   // key => 'open' | 'closed' overrides on top of the posture.
	const OPTION_ALLOWED = 'hp_allowed';  // Legacy allow-list, migrated into OPTION_STATES.

	/** @var self */
	private static $instance;

	/** True while computing a dial's base state, so our own filters step aside. */
	private $suspended = false;

	/** Constants this plugin defined itself (so the base state is still "open"). */
	private $defined = array();

	/** display_errors as PHP had it before this plugin touched it. */
	private $display_errors_base;

	/** The REST closer, kept so effective_open() can check it is still hooked. */
	private $rest_closer;

	public static function boot(): self {
		if ( ! self::$instance ) {
			self::$instance = new self();
		}
		return self::$instance;
	}

	private function __construct() {
		add_filter( 'site_status_tests', array( $this, 'register_tests' ) );
		add_filter( 'site_status_test_result', array( $this, 'escalate_core_minor_release' ) );
		add_filter( 'site_health_navigation_tabs', array( $this, 'register_tab' ) );
		add_action( 'site_health_tab_content', array( $this, 'render_tab' ) );
		add_action( 'admin_init', array( $this, 'handle_form' ) );
		add_action( 'rest_api_init', array( $this, 'register_rest_routes' ) );
		// Enforce at mu-plugin load: FORCE_SSL_ADMIN must exist before wp_ssl_constants() runs.
		$this->enforce();
	}

	/* ------------------------------------------------------------------ */
	/* Posture model                                                        */
	/* ------------------------------------------------------------------ */

	public function postures(): array {
		return array(
			'locked'   => __( 'Locked (deny by default)' ),
			'standard' => __( 'Standard (core defaults)' ),
			'open'     => __( 'Open (everything allowed)' ),
		);
	}

	public function posture(): string {
		$p = get_option( self::OPTION_POSTURE, 'standard' );
		return isset( $this->postures()[ $p ] ) ? $p : 'standard';
	}

	/** Per-dial overrides: key => 'open' | 'closed'. */
	public function states(): array {
		$states = get_option( self::OPTION_STATES, null );
		if ( null === $states ) {
			// Migrate the old allow-list once.
			$allowed = get_option( self::OPTION_ALLOWED, array() );
			$states  = array();
			foreach ( (array) $allowed as $key ) {
				$states[ sanitize_key( $key ) ] = 'open';
			}
			update_option( self::OPTION_STATES, $states );
		}
		$out = array();
		foreach ( (array) $states as $key => $state ) {
			if ( in_array( $state, array( 'open', 'closed' ), true ) ) {
				$out[ sanitize_key( $key ) ] = $state;
			}
		}
		return $out;
	}

	private function site_uses_https(): bool {
		return function_exists( 'wp_is_using_https' ) ? wp_is_using_https() : str_starts_with( home_url(), 'https://' );
	}

	/**
	 * Every dial, with:
	 *  - base_open: the state the site would be in without this plugin's enforcement
	 *  - locked_open: what the locked posture wants (true = stays open even when locked)
	 *  - constant: the wp-config.php constant that owns the dial, if any
	 *  - fix: the wp-config.php line(s) that close it permanently
	 *  - note: a warning shown next to the switch, if any
	 */
	public function dials(): array {
		$https = $this->site_uses_https();
		return array(
			'file_editor'      => array(
				'label'     => __( 'Theme and plugin file editor' ),
				'why'       => __( 'Lets administrators edit theme and plugin PHP from the dashboard. Closed, a stolen admin login cannot edit the PHP already on the server. To stop it uploading new code as well, also close installing plugins, themes and updates below.' ),
				'link'      => 'https://developer.wordpress.org/apis/wp-config-php/#disable-the-plugin-and-theme-file-editor',
				'constant'  => 'DISALLOW_FILE_EDIT',
				'base_open' => $this->constant_open( 'DISALLOW_FILE_EDIT' ),
				'fix'       => "define( 'DISALLOW_FILE_EDIT', true );",
			),
			'file_mods'        => array(
				'label'       => __( 'Installing plugins, themes and updates from the dashboard' ),
				'why'         => __( 'Lets the dashboard install, update and delete plugins and themes. Closed, new code can only arrive through your deployment process, so a stolen admin login cannot upload a plugin to run its own PHP.' ),
				'link'        => 'https://developer.wordpress.org/apis/wp-config-php/#disable-plugin-and-theme-update-and-installation',
				'constant'    => 'DISALLOW_FILE_MODS',
				'base_open'   => $this->constant_open( 'DISALLOW_FILE_MODS' ),
				'locked_open' => true, // Even a locked posture keeps updates on.
				'fix'         => "define( 'DISALLOW_FILE_MODS', true );",
				'note'        => __( 'Closing this also disables automatic updates.' ),
			),
			'unfiltered_html'  => array(
				'label'     => __( 'Unfiltered HTML for editors and admins' ),
				'why'       => __( 'Lets administrators and editors publish raw HTML, including scripts. Closed, a compromised editor account cannot plant JavaScript in your pages.' ),
				'link'      => 'https://wordpress.org/documentation/article/roles-and-capabilities/#unfiltered_html',
				'constant'  => 'DISALLOW_UNFILTERED_HTML',
				'base_open' => $this->constant_open( 'DISALLOW_UNFILTERED_HTML' ),
				'fix'       => "define( 'DISALLOW_UNFILTERED_HTML', true );",
			),
			'xmlrpc'           => array(
				'label'     => __( 'XML-RPC endpoint' ),
				'why'       => __( 'The legacy remote-publishing API used by older apps and some services. Closed, it stops the password-guessing and amplification attacks that still target it.' ),
				'link'      => 'https://developer.wordpress.org/apis/xml-rpc/',
				'base_open' => $this->without_enforcement( static fn() => (bool) apply_filters( 'xmlrpc_enabled', true ) ),
				'live'      => static fn() => (bool) apply_filters( 'xmlrpc_enabled', true ),
			),
			'app_passwords'    => array(
				'label'     => __( 'Application passwords' ),
				'why'       => __( 'Lets users mint extra passwords so apps and scripts can call the REST API. Closed, nothing can quietly create a lasting credential after a break-in.' ),
				'link'      => 'https://make.wordpress.org/core/2020/11/05/application-passwords-integration-guide/',
				'base_open' => $this->without_enforcement( static fn() => function_exists( 'wp_is_application_passwords_available' ) && wp_is_application_passwords_available() ),
				'live'      => static fn() => function_exists( 'wp_is_application_passwords_available' ) && wp_is_application_passwords_available(),
			),
			'rest_user_enum'   => array(
				'label'     => __( 'Unauthenticated REST user listing (/wp/v2/users)' ),
				'why'       => __( 'The REST API lists author slugs to anyone who asks. Closed, that listing stops. Author archives, the users sitemap and oEmbed still reveal the same slugs, so this does not hide logins on its own.' ),
				'link'      => 'https://developer.wordpress.org/rest-api/reference/users/',
				'base_open' => true, // Core default.
				'live'      => fn() => ! $this->rest_closer || false === has_filter( 'rest_request_before_callbacks', $this->rest_closer ),
			),
			'registration'     => array(
				'label'     => __( 'Open user registration' ),
				'why'       => __( 'Anyone can create an account from the login page, or from wp-signup.php on a network. Closed, spam and probe accounts cannot register themselves.' ),
				'link'      => 'https://wordpress.org/documentation/article/settings-general-screen/#membership',
				'base_open' => $this->without_enforcement( array( $this, 'registration_open' ) ),
				'live'      => array( $this, 'registration_open' ),
			),
			'outbound_http'    => array(
				'label'       => __( 'Outbound HTTP to arbitrary hosts' ),
				'why'         => __( 'WordPress can make requests to any host on the internet. Closed, a compromised plugin cannot phone home, and only the hosts you list stay reachable.' ),
				'link'        => 'https://developer.wordpress.org/apis/wp-config-php/#block-external-url-requests',
				'constant'    => 'WP_HTTP_BLOCK_EXTERNAL',
				'base_open'   => $this->constant_open( 'WP_HTTP_BLOCK_EXTERNAL' ),
				'locked_open' => true, // Updates need WordPress.org; closing keeps *.wordpress.org reachable.
				'fix'         => "define( 'WP_HTTP_BLOCK_EXTERNAL', true );\ndefine( 'WP_ACCESSIBLE_HOSTS', 'api.wordpress.org,*.wordpress.org' );",
			),
			'plain_http_admin' => array(
				'label'       => __( 'Dashboard reachable over plain HTTP' ),
				'why'         => __( 'The dashboard and login accept unencrypted connections. Closed, passwords and cookies always travel over HTTPS and cannot be read on the network.' ),
				'link'        => 'https://developer.wordpress.org/apis/wp-config-php/#require-ssl-for-admin-and-logins',
				'constant'    => 'FORCE_SSL_ADMIN',
				'base_open'   => $this->constant_open( 'FORCE_SSL_ADMIN' ),
				'locked_open' => ! $https, // Never lock an HTTP-only site out of its own admin.
				'fix'         => "define( 'FORCE_SSL_ADMIN', true );",
				'note'        => $https ? '' : __( 'This site is not served over HTTPS. Closing this would redirect the dashboard to an address that does not work.' ),
			),
			'debug_display'    => array(
				'label'     => __( 'Errors displayed to visitors' ),
				'why'       => __( 'PHP errors are printed into pages. Closed, visitors never see file paths, queries and other details that help an attacker.' ),
				'link'      => 'https://developer.wordpress.org/advanced-administration/debug/debug-wordpress/#wp_debug_display',
				'base_open' => $this->display_errors_base(),
				'live'      => static fn() => in_array( strtolower( trim( (string) ini_get( 'display_errors' ) ) ), array( '1', 'on', 'true', 'yes', 'stdout', 'stderr' ), true ),
				'fix'       => "define( 'WP_DEBUG_DISPLAY', false );\n// WP_DEBUG_DISPLAY only applies when WP_DEBUG is on; php.ini decides otherwise:\n@ini_set( 'display_errors', '0' );",
			),
			'pingbacks'        => array(
				'label'     => __( 'Pingbacks and trackbacks on new posts' ),
				'why'       => __( 'New posts accept pingbacks and trackbacks from other sites. Closed, the site cannot be used as a reflector in attacks and gets less link spam.' ),
				'link'      => 'https://wordpress.org/documentation/article/trackbacks-and-pingbacks/',
				'base_open' => $this->without_enforcement( static fn() => 'open' === get_option( 'default_ping_status' ) ),
				'live'      => static fn() => 'open' === get_option( 'default_ping_status' ),
			),
		);
	}

	/**
	 * Whether anyone can sign up. On a network the login form hands off to wp-signup.php, which
	 * reads the network's "registration" setting instead of users_can_register.
	 */
	public function registration_open(): bool {
		if ( is_multisite() ) {
			$active = apply_filters( 'wpmu_active_signup', get_site_option( 'registration', 'none' ) );
			if ( in_array( $active, array( 'user', 'all' ), true ) ) {
				return true;
			}
		}
		return (bool) get_option( 'users_can_register' );
	}

	/** Whether PHP displays errors, read once before enforcement so our own ini_set does not hide it. */
	private function display_errors_base(): bool {
		if ( null === $this->display_errors_base ) {
			$value                     = strtolower( trim( (string) ini_get( 'display_errors' ) ) );
			$this->display_errors_base = in_array( $value, array( '1', 'on', 'true', 'yes', 'stdout', 'stderr' ), true );
		}
		return $this->display_errors_base;
	}

	/** A constant-backed dial is open unless the constant is truthy, or we defined it ourselves. */
	private function constant_open( string $name ): bool {
		if ( in_array( $name, $this->defined, true ) ) {
			return true;
		}
		return ! ( defined( $name ) && constant( $name ) );
	}

	/** Run a probe with our own runtime filters stepping aside. */
	private function without_enforcement( callable $probe ): bool {
		$this->suspended = true;
		try {
			return (bool) $probe();
		} finally {
			$this->suspended = false;
		}
	}

	/** True when the dial's constant was set in wp-config.php (or elsewhere), so the switch cannot move it. */
	public function pinned( array $dial ): bool {
		return ! empty( $dial['constant'] ) && defined( $dial['constant'] ) && ! in_array( $dial['constant'], $this->defined, true );
	}

	/** What the posture alone wants, before per-dial overrides. */
	public function posture_default_open( string $key, array $dial, ?string $posture = null ): bool {
		switch ( $posture ?? $this->posture() ) {
			case 'locked':
				return ! empty( $dial['locked_open'] );
			case 'open':
				return true;
			default:
				return (bool) $dial['base_open'];
		}
	}

	/** What the site owner wants this dial to be: override, else posture default. */
	public function desired_open( string $key, array $dial ): bool {
		$states = $this->states();
		if ( isset( $states[ $key ] ) ) {
			return 'open' === $states[ $key ];
		}
		return $this->posture_default_open( $key, $dial );
	}

	/**
	 * What the dial actually is right now. Constant-backed dials are known from the constant;
	 * everything else is measured live, with every plugin's hooks in place, so a later plugin
	 * that reopens a feature shows up as drift instead of hiding behind our stored intent.
	 */
	public function effective_open( string $key, array $dial ): bool {
		if ( ! empty( $dial['live'] ) ) {
			return (bool) call_user_func( $dial['live'] );
		}
		if ( ! $dial['base_open'] ) {
			return false; // Closed by the site itself; we never force things open.
		}
		if ( $this->pinned( $dial ) ) {
			return true; // Constant set in wp-config.php as "open"; we cannot close it.
		}
		return $this->desired_open( $key, $dial );
	}

	/** Dials that are open although the owner wants them closed. */
	public function drift(): array {
		$drift = array();
		foreach ( $this->dials() as $key => $dial ) {
			if ( $this->effective_open( $key, $dial ) && ! $this->desired_open( $key, $dial ) ) {
				$drift[ $key ] = $dial;
			}
		}
		return $drift;
	}

	/**
	 * Runtime enforcement: closes every dial whose desired state is closed. Constant-backed
	 * dials are skipped when wp-config.php already settled them. Filter-backed closers are
	 * installed regardless of what the base state looks like at mu-plugin load, because that
	 * sample is taken before any other plugin has hooked anything.
	 */
	public function enforce(): void {
		foreach ( $this->dials() as $key => $dial ) {
			if ( $this->desired_open( $key, $dial ) ) {
				continue;
			}
			if ( ! empty( $dial['constant'] ) && ( $this->pinned( $dial ) || ! $dial['base_open'] ) ) {
				continue;
			}
			switch ( $key ) {
				case 'file_editor':
					$this->define( 'DISALLOW_FILE_EDIT', true );
					break;
				case 'file_mods':
					$this->define( 'DISALLOW_FILE_MODS', true );
					break;
				case 'unfiltered_html':
					$this->define( 'DISALLOW_UNFILTERED_HTML', true );
					break;
				case 'outbound_http':
					$this->define( 'WP_HTTP_BLOCK_EXTERNAL', true );
					if ( ! defined( 'WP_ACCESSIBLE_HOSTS' ) ) {
						define( 'WP_ACCESSIBLE_HOSTS', 'api.wordpress.org,*.wordpress.org' );
					}
					break;
				case 'plain_http_admin':
					$this->define( 'FORCE_SSL_ADMIN', true );
					break;
				case 'debug_display':
					ini_set( 'display_errors', '0' );
					break;
				case 'xmlrpc':
					add_filter( 'xmlrpc_enabled', fn( $v ) => $this->suspended ? $v : false, PHP_INT_MAX );
					if ( defined( 'XMLRPC_REQUEST' ) && XMLRPC_REQUEST ) {
						status_header( 403 );
						nocache_headers();
						exit( 'XML-RPC is closed by the site hardening posture.' );
					}
					break;
				case 'app_passwords':
					add_filter( 'wp_is_application_passwords_available', fn( $v ) => $this->suspended ? $v : false, PHP_INT_MAX );
					break;
				case 'rest_user_enum':
					// Route matching in core is case-insensitive, so "/wp/v2/USERS" reaches the users
					// controller too. Match the path case-insensitively and also the handler itself.
					$this->rest_closer = function ( $response, $handler, $request ) {
							if ( $this->suspended || is_wp_error( $response ) || is_user_logged_in() ) {
								return $response;
							}
							$users_route    = (bool) preg_match( '#^/wp/v2/users(/|$)#i', $request->get_route() );
							$users_callback = is_array( $handler['callback'] ?? null ) && ( $handler['callback'][0] ?? null ) instanceof WP_REST_Users_Controller;
							if ( $users_route || $users_callback ) {
								return new WP_Error( 'hp_closed', __( 'User listing is closed by the site hardening posture.' ), array( 'status' => 401 ) );
							}
							return $response;
					};
					add_filter( 'rest_request_before_callbacks', $this->rest_closer, PHP_INT_MAX, 3 );
					break;
				case 'registration':
					// pre_option_* short-circuits get_option() before option_* filters run, so a later
					// plugin using it cannot slip past an option_* closer. Use the same lever.
					add_filter( 'pre_option_users_can_register', fn( $v ) => $this->suspended ? $v : '0', PHP_INT_MAX );
					if ( is_multisite() ) {
						// wp-signup.php never reads users_can_register; it asks the network setting through this filter.
						add_filter(
							'wpmu_active_signup',
							function ( $active ) {
								if ( $this->suspended ) {
									return $active;
								}
								return 'all' === $active ? 'blog' : ( 'user' === $active ? 'none' : $active );
							},
							PHP_INT_MAX
						);
					}
					break;
				case 'pingbacks':
					add_filter( 'pre_option_default_ping_status', fn( $v ) => $this->suspended ? $v : 'closed', PHP_INT_MAX );
					add_filter( 'xmlrpc_methods', static function ( $m ) { unset( $m['pingback.ping'], $m['pingback.extensions.getPingbacks'] ); return $m; } );
					break;
			}
		}
	}

	private function define( string $name, $value ): void {
		if ( ! defined( $name ) ) {
			define( $name, $value );
			$this->defined[] = $name;
		}
	}

	/* ------------------------------------------------------------------ */
	/* Site Health: Status tab tests                                        */
	/* ------------------------------------------------------------------ */

	/**
	 * Core's wordpress_version test only looks at offers with response "upgrade",
	 * because get_core_updates() drops "autoupdate" offers. When the latest release
	 * is a new major, the pending minor (security) release in the installed branch
	 * is never reported and the result is a mere "recommended". Fix: scan every
	 * offer for a newer release in the installed branch and escalate.
	 */
	public function escalate_core_minor_release( $result ) {
		if ( ! is_array( $result ) || ( $result['test'] ?? '' ) !== 'wordpress_version' ) {
			return $result;
		}
		$from_api = get_site_transient( 'update_core' );
		if ( empty( $from_api->updates ) || ! is_array( $from_api->updates ) ) {
			return $result;
		}
		$current = wp_get_wp_version();
		$branch  = implode( '.', array_slice( explode( '.', $current ), 0, 2 ) );
		$minor   = null;
		$latest  = null;
		foreach ( $from_api->updates as $offer ) {
			if ( 'development' === ( $offer->response ?? '' ) ) {
				continue; // Nightlies are not releases.
			}
			$version = $offer->current ?? ( $offer->version ?? '' );
			if ( ! $version || ! version_compare( $version, $current, '>' ) ) {
				continue;
			}
			if ( ! $latest || version_compare( $version, $latest, '>' ) ) {
				$latest = $version;
			}
			if ( str_starts_with( $version, $branch . '.' ) && ( ! $minor || version_compare( $version, $minor, '>' ) ) ) {
				$minor = $version;
			}
		}
		if ( ! $minor ) {
			return $result;
		}

		$result['status']         = 'critical';
		$result['badge']['label'] = __( 'Security' );
		$result['badge']['color'] = 'red';
		$result['label']          = sprintf(
			/* translators: 1: pending minor release, 2: installed branch */
			__( 'WordPress %1$s is a pending maintenance and security release for your %2$s branch' ),
			$minor,
			$branch
		);
		$result['description'] = sprintf(
			'<p>%s</p>',
			sprintf(
				/* translators: 1: installed version, 2: pending minor release */
				__( 'You are running %1$s. Minor releases on your branch carry security fixes, and %2$s has not been installed. This is reported as critical regardless of whether a newer major version also exists.' ),
				$current,
				$minor
			)
		);
		if ( $latest && $latest !== $minor ) {
			$result['description'] .= sprintf(
				'<p>%s</p>',
				sprintf(
					/* translators: %s: latest major release */
					__( 'A newer major version, %s, is also available. Upgrading to it includes these fixes, but the minor release is the smaller, safer step if you cannot test a major upgrade right now.' ),
					$latest
				)
			);
		}
		$result['actions'] = sprintf(
			'<p><a href="%s">%s</a></p>',
			esc_url( admin_url( 'update-core.php' ) ),
			__( 'Install the pending release' )
		);
		return $result;
	}

	/** Tests that make HTTP requests to the site itself; they run async so the page never waits on them. */
	const LOOPBACK_TESTS = array( 'upload_exec', 'exposed_files', 'server_hygiene' );

	public function register_tests( array $tests ): array {
		$labels = array(
			'posture_drift'   => __( 'Hardening posture' ),
			'url_match'       => __( 'Address bar matches the site address' ),
			'php_confinement' => __( 'PHP process confinement' ),
			'environment'     => __( 'Configuration hygiene' ),
			'db_privileges'   => __( 'Database user privileges' ),
			'supply_chain'    => __( 'Plugins outside the directory' ),
			'upload_exec'     => __( 'PHP execution in uploads' ),
			'exposed_files'   => __( 'Exposed files' ),
			'server_hygiene'  => __( 'Web server hygiene' ),
		);
		foreach ( $labels as $key => $label ) {
			if ( in_array( $key, self::LOOPBACK_TESTS, true ) ) {
				// Same shape as core's loopback test: the browser fetches it, cron calls it directly.
				$tests['async'][ 'hp_' . $key ] = array(
					'label'             => $label,
					'test'              => rest_url( 'hp/v1/tests/' . str_replace( '_', '-', $key ) ),
					'has_rest'          => true,
					'async_direct_test' => array( $this, 'test_' . $key ),
				);
			} else {
				$tests['direct'][ 'hp_' . $key ] = array(
					'label' => $label,
					'test'  => array( $this, 'test_' . $key ),
				);
			}
		}
		return $tests;
	}

	public function register_rest_routes(): void {
		register_rest_route(
			'hp/v1',
			'/tests/(?P<test>[a-z-]+)',
			array(
				'methods'             => 'GET',
				'permission_callback' => static fn() => current_user_can( 'view_site_health_checks' ),
				'callback'            => function ( WP_REST_Request $request ) {
					$key = str_replace( '-', '_', $request['test'] );
					if ( ! in_array( $key, self::LOOPBACK_TESTS, true ) ) {
						return new WP_Error( 'rest_no_route', __( 'No such test.' ), array( 'status' => 404 ) );
					}
					return rest_ensure_response( $this->{'test_' . $key}() );
				},
			)
		);
	}

	private function result( string $test, string $label, string $status, string $desc, string $actions = '' ): array {
		return array(
			'label'       => $label,
			'status'      => $status,
			'badge'       => array( 'label' => __( 'Hardening' ), 'color' => 'red' ),
			'description' => $desc,
			'actions'     => $actions,
			'test'        => 'hp_' . $test,
		);
	}

	private function list_html( array $items ): string {
		return '<ul style="list-style:disc;margin-left:1.5em">' . implode( '', array_map( static fn( $i ) => '<li>' . $i . '</li>', $items ) ) . '</ul>';
	}

	private function tab_link(): string {
		return '<p><a href="' . esc_url( admin_url( 'site-health.php?tab=hardening' ) ) . '">' . __( 'Review the Hardening posture' ) . '</a></p>';
	}

	public function test_posture_drift(): array {
		$drift = $this->drift();
		$label = $this->postures()[ $this->posture() ];
		if ( ! $drift ) {
			return $this->result( 'posture_drift', sprintf( __( 'Site matches its "%s" posture' ), $label ), 'good', '<p>' . __( 'Every hardening dial is in the state the site owner set on the Hardening tab.' ) . '</p>', $this->tab_link() );
		}
		$items = array_map( static fn( $d ) => esc_html( $d['label'] ), $drift );
		return $this->result(
			'posture_drift',
			sprintf( _n( '%d feature is open that is switched to closed (posture: %s)', '%d features are open that are switched to closed (posture: %s)', count( $drift ) ), count( $drift ), $label ),
			'critical',
			'<p>' . __( 'These are switched to closed on the Hardening tab but are still reachable, usually because wp-config.php pins them open. Change the constant there, or switch them to open deliberately.' ) . '</p>' . $this->list_html( $items ),
			$this->tab_link()
		);
	}

	/**
	 * The host and scheme the browser used must be the ones in Settings > General. When they
	 * differ, the server answers under names WordPress does not know about (host-header
	 * injection, cache poisoning, password-reset links to the wrong host) or sits behind a
	 * proxy whose HTTPS WordPress cannot see (insecure cookies, redirect loops).
	 */
	public function test_url_match(): array {
		$host = strtolower( trim( (string) ( $_SERVER['HTTP_HOST'] ?? '' ) ) );
		if ( '' === $host || wp_doing_cron() || ( defined( 'WP_CLI' ) && WP_CLI ) ) {
			return $this->result( 'url_match', __( 'The address bar check runs when Site Health is opened in a browser' ), 'good', '<p>' . __( 'This run had no browser request to compare against.' ) . '</p>' );
		}
		$normalize = static function ( string $scheme, string $host ): string {
			$scheme = strtolower( $scheme );
			$host   = strtolower( $host );
			if ( str_ends_with( $host, 'http' === $scheme ? ':80' : ':443' ) ) {
				$host = substr( $host, 0, strrpos( $host, ':' ) );
			}
			return $scheme . '://' . $host;
		};
		$seen      = $normalize( is_ssl() ? 'https' : 'http', $host );
		$mismatch  = array();
		$host_diff = false;
		// Raw options, not home_url(): that helper already swaps in https on an SSL request.
		foreach ( array( __( 'Site Address (URL)' ) => get_option( 'home' ), __( 'WordPress Address (URL)' ) => get_option( 'siteurl' ) ) as $setting => $url ) {
			$u          = wp_parse_url( (string) $url );
			$configured = $normalize( $u['scheme'] ?? 'http', ( $u['host'] ?? '' ) . ( isset( $u['port'] ) ? ':' . $u['port'] : '' ) );
			if ( $configured !== $seen ) {
				$mismatch[] = sprintf( __( '%1$s is <code>%2$s</code>, the browser used <code>%3$s</code>.' ), $setting, esc_html( $configured ), esc_html( $seen ) );
				if ( substr( $configured, strpos( $configured, '://' ) ) !== substr( $seen, strpos( $seen, '://' ) ) ) {
					$host_diff = true;
				}
			}
		}
		if ( ! $mismatch ) {
			return $this->result( 'url_match', __( 'The address bar matches the configured site address' ), 'good', sprintf( '<p>' . __( 'This page was requested as <code>%s</code>, which is the address WordPress is configured with.' ) . '</p>', esc_html( $seen ) ) );
		}
		return $this->result(
			'url_match',
			$host_diff ? __( 'The site is reachable under an address it is not configured for' ) : __( 'The site is configured with a different scheme than the browser used' ),
			$host_diff ? 'critical' : 'recommended',
			'<p>' . __( 'WordPress builds links, cookies, redirects and password-reset emails from the configured address. Answering under another one means the web server accepts any Host header, or a proxy in front hides the real scheme.' ) . '</p>' . $this->list_html( $mismatch ),
			'<p>' . sprintf( __( 'Fix the addresses under <a href="%s">Settings &rsaquo; General</a>, make the web server answer only for the configured host, and if a proxy terminates HTTPS, tell WordPress about it with <code>HTTP_X_FORWARDED_PROTO</code> handling in wp-config.php.' ), esc_url( admin_url( 'options-general.php' ) ) ) . '</p>'
		);
	}

	public function test_php_confinement(): array {
		$issues = array();
		$good   = array();

		$ob = ini_get( 'open_basedir' );
		if ( $ob ) {
			$good[] = 'open_basedir = <code>' . esc_html( $ob ) . '</code>';
		} else {
			$issues[] = __( '<code>open_basedir</code> is not set: PHP can read any file the process user can.' );
		}

		$df = ini_get( 'disable_functions' );
		if ( $df ) {
			$good[] = 'disable_functions = <code>' . esc_html( $df ) . '</code>';
		} else {
			$issues[] = __( '<code>disable_functions</code> is empty: <code>exec</code>, <code>shell_exec</code>, <code>proc_open</code> are all callable.' );
		}

		if ( filter_var( ini_get( 'allow_url_include' ), FILTER_VALIDATE_BOOLEAN ) ) {
			$issues[] = __( '<code>allow_url_include</code> is on: remote file inclusion is one bug away.' );
		}
		if ( filter_var( ini_get( 'expose_php' ), FILTER_VALIDATE_BOOLEAN ) ) {
			$issues[] = __( '<code>expose_php</code> is on: the PHP version is advertised in every response.' );
		}

		$code_writable = is_writable( ABSPATH . 'wp-includes' ) && is_writable( ABSPATH . 'wp-includes/version.php' );
		$owner_match   = function_exists( 'fileowner' ) && function_exists( 'posix_geteuid' ) && fileowner( ABSPATH . 'wp-includes/version.php' ) === posix_geteuid();
		if ( $code_writable ) {
			$issues[] = __( 'The PHP process can write to <code>wp-includes</code>. A code-execution bug in any plugin becomes a persistent backdoor.' ) . ( $owner_match ? ' ' . __( '(The process user owns the code files.)' ) : '' );
		} else {
			$good[] = __( 'Core code directories are not writable by the PHP process.' );
		}

		$sapi = PHP_SAPI;
		if ( 'cli-server' === $sapi ) {
			$issues[] = __( 'Running under the PHP built-in server, which is for development only.' );
		}

		$status = $issues ? ( $code_writable || ! $df ? 'critical' : 'recommended' ) : 'good';
		$label  = $issues ? sprintf( _n( '%d PHP confinement issue found', '%d PHP confinement issues found', count( $issues ) ), count( $issues ) ) : __( 'The PHP process is confined' );
		$desc   = '<p>' . __( 'Whether a compromised plugin can reach the operating system or rewrite the site itself.' ) . '</p>';
		$desc  .= $issues ? $this->list_html( $issues ) : '';
		$desc  .= $good ? '<p><strong>' . __( 'In place:' ) . '</strong></p>' . $this->list_html( $good ) : '';
		return $this->result( 'php_confinement', $label, $status, $desc );
	}

	public function test_environment(): array {
		global $table_prefix;
		$issues = array();

		if ( ! defined( 'WP_ENVIRONMENT_TYPE' ) && 'production' === wp_get_environment_type() ) {
			$issues[] = __( '<code>WP_ENVIRONMENT_TYPE</code> is not declared, so WordPress assumes production for every decision.' );
		}
		if ( 'wp_' === $table_prefix ) {
			$issues[] = __( 'The database table prefix is the default <code>wp_</code>.' );
		}
		foreach ( array( 'AUTH_KEY', 'SECURE_AUTH_KEY', 'LOGGED_IN_KEY', 'NONCE_KEY', 'AUTH_SALT', 'SECURE_AUTH_SALT', 'LOGGED_IN_SALT', 'NONCE_SALT' ) as $k ) {
			if ( ! defined( $k ) || 'put your unique phrase here' === constant( $k ) || strlen( constant( $k ) ) < 32 ) {
				$issues[] = sprintf( __( 'Secret key <code>%s</code> is missing, the placeholder, or too short.' ), $k );
			}
		}
		if ( file_exists( ABSPATH . 'wp-config.php' ) ) {
			$issues[] = __( '<code>wp-config.php</code> lives inside the web root. Moving it one directory up keeps credentials out of reach if PHP ever stops executing.' );
		}
		if ( file_exists( ABSPATH . 'wp-config-sample.php' ) || file_exists( ABSPATH . 'readme.html' ) ) {
			$issues[] = __( '<code>wp-config-sample.php</code> or <code>readme.html</code> still ship with the install and reveal the version.' );
		}
		$dials = $this->dials();
		if ( $this->effective_open( 'file_editor', $dials['file_editor'] ) ) {
			$issues[] = __( 'The theme and plugin file editor is enabled.' );
		}
		if ( get_user_by( 'login', 'admin' ) ) {
			$issues[] = __( 'A user named <code>admin</code> exists. Credential-stuffing bots try it first.' );
		}

		$status = $issues ? 'recommended' : 'good';
		$label  = $issues ? sprintf( _n( '%d configuration hygiene item to fix', '%d configuration hygiene items to fix', count( $issues ) ), count( $issues ) ) : __( 'Configuration hygiene looks good' );
		return $this->result( 'environment', $label, $status, '<p>' . __( 'Defaults that are harmless on day one and expensive on day one thousand.' ) . '</p>' . $this->list_html( $issues ) );
	}

	public function test_db_privileges(): array {
		global $wpdb;
		$issues = array();
		$grants = $wpdb->get_col( 'SHOW GRANTS FOR CURRENT_USER()' );
		$all    = implode( "\n", (array) $grants );

		if ( preg_match( '/GRANT ALL PRIVILEGES ON \*\.\*/i', $all ) ) {
			$issues[] = __( 'The application user has ALL PRIVILEGES on every database on the server.' );
		}
		foreach ( array( 'FILE', 'SUPER', 'PROCESS', 'SHUTDOWN', 'CREATE USER', 'GRANT OPTION' ) as $priv ) {
			if ( preg_match( '/\b' . preg_quote( $priv, '/' ) . '\b/i', $all ) ) {
				$issues[] = sprintf( __( 'The application user holds the <code>%s</code> privilege, which WordPress never needs.' ), $priv );
			}
		}
		if ( preg_match( "/TO [`']?[^`'@]+[`']?@[`']?%[`']?/", $all ) ) {
			$issues[] = __( 'The application user may connect from any host (<code>@%</code>).' );
		}
		$host = DB_HOST;
		if ( ! preg_match( '/^(localhost|127\.0\.0\.1|::1)(:\d+)?$|^localhost:\//', $host ) ) {
			$issues[] = sprintf( __( 'The database is reached over the network at <code>%s</code>; make sure it is not also reachable from the internet.' ), esc_html( $host ) );
		}

		$status = $issues ? 'recommended' : 'good';
		$label  = $issues ? sprintf( _n( '%d database privilege issue', '%d database privilege issues', count( $issues ) ), count( $issues ) ) : __( 'The database user is scoped to this site' );
		$desc   = '<p>' . __( 'What an SQL injection in any plugin would be able to do beyond this site&#8217;s tables.' ) . '</p>' . $this->list_html( $issues );
		$desc  .= '<details><summary>' . __( 'Grants seen' ) . '</summary><pre>' . esc_html( $all ) . '</pre></details>';
		return $this->result( 'db_privileges', $label, $status, $desc );
	}

	public function test_supply_chain(): array {
		if ( ! function_exists( 'get_plugins' ) ) {
			require_once ABSPATH . 'wp-admin/includes/plugin.php';
		}
		$plugins = get_plugins();
		$update  = get_site_transient( 'update_plugins' );
		if ( empty( $update->last_checked ) ) {
			wp_update_plugins();
			$update = get_site_transient( 'update_plugins' );
		}
		if ( empty( $update->last_checked ) ) {
			return $this->result( 'supply_chain', __( 'Could not check plugins against the directory' ), 'recommended', '<p>' . __( 'WordPress has not been able to ask WordPress.org about installed plugins yet, so untracked plugins cannot be told apart from tracked ones.' ) . '</p>' );
		}
		$known   = array_merge( array_keys( (array) ( $update->response ?? array() ) ), array_keys( (array) ( $update->no_update ?? array() ) ) );
		$orphans = array();
		foreach ( $plugins as $file => $data ) {
			if ( ! in_array( $file, $known, true ) ) {
				$orphans[] = esc_html( $data['Name'] ) . ( is_plugin_active( $file ) ? '' : ' <em>(' . __( 'inactive' ) . ')</em>' );
			}
		}
		if ( ! $orphans ) {
			return $this->result( 'supply_chain', __( 'Every plugin is tracked by the WordPress.org directory' ), 'good', '<p>' . __( 'Updates and closure notices will reach this site.' ) . '</p>' );
		}
		return $this->result(
			'supply_chain',
			sprintf( _n( '%d plugin is not tracked by the directory', '%d plugins are not tracked by the directory', count( $orphans ) ), count( $orphans ) ),
			'recommended',
			'<p>' . __( 'These plugins get no update or closure notices from WordPress.org. They may be premium, custom, or removed from the directory for a security reason.' ) . '</p>' . $this->list_html( $orphans )
		);
	}

	/** Shared helper for the three request-based checks. */
	private function fetch( string $url ): array {
		$r = wp_remote_get( $url, array( 'timeout' => 5, 'sslverify' => apply_filters( 'https_local_ssl_verify', false, $url ), 'redirection' => 0, 'headers' => array( 'Cache-Control' => 'no-cache' ) ) );
		if ( is_wp_error( $r ) ) {
			return array( 'code' => 0, 'body' => '', 'headers' => array(), 'error' => $r->get_error_message() );
		}
		return array( 'code' => wp_remote_retrieve_response_code( $r ), 'body' => (string) wp_remote_retrieve_body( $r ), 'headers' => wp_remote_retrieve_headers( $r ), 'error' => '' );
	}

	public function test_upload_exec(): array {
		$uploads = wp_upload_dir();
		$marker  = 'HP_EXEC_' . wp_generate_password( 12, false );
		$name    = 'hp-probe-' . wp_generate_password( 16, false ) . '.php';
		$path    = trailingslashit( $uploads['basedir'] ) . $name;
		// Request the probe from this server, not from a CDN that media plugins put into baseurl.
		$abspath = trailingslashit( wp_normalize_path( ABSPATH ) );
		$local   = wp_normalize_path( $path );
		$url     = str_starts_with( $local, $abspath )
			? site_url( '/' . substr( $local, strlen( $abspath ) ) )
			: trailingslashit( $uploads['baseurl'] ) . $name;

		if ( false === @file_put_contents( $path, "<?php echo '" . $marker . "';" ) ) {
			return $this->result( 'upload_exec', __( 'Could not write a probe into the uploads directory' ), 'recommended', '<p>' . __( 'The check needs to drop a one-line PHP file into uploads and request it.' ) . '</p>' );
		}
		$res = $this->fetch( $url );
		@unlink( $path );

		if ( str_contains( $res['body'], $marker ) ) {
			return $this->result( 'upload_exec', __( 'PHP files in the uploads directory execute' ), 'critical', '<p>' . __( 'A probe written to <code>wp-content/uploads</code> ran when requested. Any upload bypass in any plugin is therefore remote code execution.' ) . '</p>', '<p>' . __( 'Deny PHP execution under uploads at the web server: for Apache a <code>.htaccess</code> with <code>php_flag engine off</code> or a <code>&lt;FilesMatch "\.php$"&gt; Require all denied</code>; for nginx a <code>location ~* /uploads/.*\.php$ { deny all; }</code>.' ) . '</p>' );
		}
		if ( 0 === $res['code'] ) {
			return $this->result( 'upload_exec', __( 'Could not request the uploads probe' ), 'recommended', '<p>' . esc_html( $res['error'] ) . '</p>' );
		}
		return $this->result( 'upload_exec', __( 'PHP files in the uploads directory do not execute' ), 'good', sprintf( '<p>' . __( 'The probe returned HTTP %d without running.' ) . '</p>', $res['code'] ) );
	}

	public function test_exposed_files(): array {
		// Core files live under site_url(), not home_url(), on subdirectory installs; wp-content can be
		// relocated, so its probes go through content_url(). Matchers look for each file's own
		// signature so a host that answers 200 for unknown paths does not light everything up.
		$listing = static fn( $b ) => (bool) preg_match( '#<title>\s*Index of#i', $b );
		$targets = array(
			'wp-config.php'     => array( site_url( '/wp-config.php' ), static fn( $b ) => str_contains( $b, 'DB_NAME' ) ),
			'wp-config.php.bak' => array( site_url( '/wp-config.php.bak' ), static fn( $b ) => str_contains( $b, 'DB_NAME' ) ),
			'wp-config.php~'    => array( site_url( '/wp-config.php~' ), static fn( $b ) => str_contains( $b, 'DB_NAME' ) ),
			'.env'              => array( site_url( '/.env' ), static fn( $b ) => (bool) preg_match( '/^[A-Z_][A-Z0-9_]*=/m', $b ) ),
			'.git/HEAD'         => array( site_url( '/.git/HEAD' ), static fn( $b ) => str_starts_with( $b, 'ref:' ) ),
			'debug.log'         => array( content_url( '/debug.log' ), static fn( $b ) => (bool) preg_match( '/^\[\d{2}-[A-Za-z]{3}-\d{4} \d{2}:\d{2}:\d{2} [A-Z]+\]/m', $b ) ),
			'readme.html'       => array( site_url( '/readme.html' ), static fn( $b ) => str_contains( $b, 'WordPress &#8250; ReadMe' ) ),
			'license.txt'       => array( site_url( '/license.txt' ), static fn( $b ) => str_contains( $b, 'WordPress - Web publishing software' ) ),
			'uploads/'          => array( content_url( '/uploads/' ), $listing ),
			'wp-includes/'      => array( site_url( '/wp-includes/' ), $listing ),
		);
		$exposed = array();
		foreach ( $targets as $rel => [ $url, $matches ] ) {
			$res = $this->fetch( $url );
			if ( 200 === $res['code'] && $matches( $res['body'] ) ) {
				$exposed[] = '<code>' . esc_html( $rel ) . '</code>';
			}
		}
		if ( ! $exposed ) {
			return $this->result( 'exposed_files', __( 'No sensitive files are readable over HTTP' ), 'good', '<p>' . __( 'Config backups, logs, version files and directory listings all return nothing useful.' ) . '</p>' );
		}
		$critical = (bool) array_intersect( $exposed, array( '<code>wp-config.php</code>', '<code>wp-config.php.bak</code>', '<code>wp-config.php~</code>', '<code>.env</code>', '<code>.git/HEAD</code>' ) );
		return $this->result(
			'exposed_files',
			sprintf( _n( '%d file is readable over HTTP that should not be', '%d files are readable over HTTP that should not be', count( $exposed ) ), count( $exposed ) ),
			$critical ? 'critical' : 'recommended',
			'<p>' . __( 'Each of these was requested from this site and returned content.' ) . '</p>' . $this->list_html( $exposed ),
			'<p>' . __( 'Deny them at the web server, delete the ones that are not needed, and move logs out of the web root.' ) . '</p>'
		);
	}

	public function test_server_hygiene(): array {
		$res    = $this->fetch( home_url( '/' ) );
		$h      = $res['headers'];
		$issues = array();
		$good   = array();

		if ( 0 === $res['code'] ) {
			return $this->result( 'server_hygiene', __( 'Could not request the home page' ), 'recommended', '<p>' . esc_html( $res['error'] ) . '</p>' );
		}
		$server = (string) ( $h['server'] ?? '' );
		if ( preg_match( '/\d+\.\d+/', $server ) ) {
			$issues[] = sprintf( __( 'The <code>Server</code> header advertises a version: <code>%s</code>.' ), esc_html( $server ) );
		}
		if ( ! empty( $h['x-powered-by'] ) ) {
			$issues[] = sprintf( __( '<code>X-Powered-By</code> advertises <code>%s</code>.' ), esc_html( $h['x-powered-by'] ) );
		}
		foreach ( array( 'x-content-type-options' => 'nosniff', 'x-frame-options' => 'SAMEORIGIN', 'referrer-policy' => 'strict-origin-when-cross-origin', 'content-security-policy' => null, 'permissions-policy' => null ) as $name => $hint ) {
			if ( empty( $h[ $name ] ) ) {
				$issues[] = sprintf( __( 'Missing <code>%s</code> header%s.' ), $name, $hint ? ' (' . $hint . ')' : '' );
			} else {
				$good[] = '<code>' . $name . '</code>';
			}
		}
		if ( is_ssl() || str_starts_with( home_url(), 'https://' ) ) {
			if ( empty( $h['strict-transport-security'] ) ) {
				$issues[] = __( 'Missing <code>Strict-Transport-Security</code> on an HTTPS site.' );
			} else {
				$good[] = '<code>strict-transport-security</code>';
			}
		} else {
			$issues[] = __( 'The site is served over plain HTTP, so every cookie and password crosses the wire in clear text.' );
		}

		$status = $issues ? ( str_starts_with( home_url(), 'http://' ) ? 'critical' : 'recommended' ) : 'good';
		$label  = $issues ? sprintf( _n( '%d web server hygiene issue', '%d web server hygiene issues', count( $issues ) ), count( $issues ) ) : __( 'Web server headers look good' );
		$desc   = '<p>' . __( 'What the web server tells attackers, and what it refuses to tell browsers.' ) . '</p>' . $this->list_html( $issues );
		$desc  .= $good ? '<p><strong>' . __( 'Present:' ) . '</strong> ' . implode( ', ', $good ) . '</p>' : '';
		return $this->result( 'server_hygiene', $label, $status, $desc );
	}

	/* ------------------------------------------------------------------ */
	/* Site Health: Hardening tab                                           */
	/* ------------------------------------------------------------------ */

	public function register_tab( array $tabs ): array {
		$tabs['hardening'] = __( 'Hardening' );
		return $tabs;
	}

	public function handle_form(): void {
		if ( empty( $_POST['hp_save'] ) || ! current_user_can( 'manage_options' ) ) {
			return;
		}
		check_admin_referer( 'hp_save_posture' );
		$posture = sanitize_key( $_POST['hp_posture'] ?? 'standard' );
		$posture     = isset( $this->postures()[ $posture ] ) ? $posture : 'standard';
		$old_posture = $this->posture();
		update_option( self::OPTION_POSTURE, $posture );

		// The switches were drawn for the posture the page loaded with. Only a switch the user
		// flipped is their intent; an untouched switch follows the new posture when the posture
		// changed, and keeps its value otherwise. Overrides are stored only where the result
		// differs from the new posture's default, so a later posture change re-applies defaults.
		$posted   = (array) ( $_POST['hp_state'] ?? array() );
		$rendered = (array) ( $_POST['hp_rendered'] ?? array() );
		$changed  = $posture !== $old_posture;
		$states   = array();
		foreach ( $this->dials() as $key => $dial ) {
			if ( $this->pinned( $dial ) ) {
				continue;
			}
			$default = $this->posture_default_open( $key, $dial, $posture );
			$want    = ! empty( $posted[ $key ] );
			$shown   = ! empty( $rendered[ $key ] );
			if ( $want === $shown && $changed ) {
				$want = $default;
			}
			if ( $want !== $default ) {
				$states[ $key ] = $want ? 'open' : 'closed';
			}
		}
		update_option( self::OPTION_STATES, $states );
		wp_safe_redirect( admin_url( 'site-health.php?tab=hardening&saved=1' ) );
		exit;
	}

	public function render_tab( string $tab ): void {
		if ( 'hardening' !== $tab ) {
			return;
		}
		$posture = $this->posture();
		$dials   = $this->dials();
		$drift   = $this->drift();
		$open    = 0;
		foreach ( $dials as $key => $dial ) {
			$open += $this->effective_open( $key, $dial ) ? 1 : 0;
		}
		$blurbs = array(
			'locked'   => __( 'Everything closes except dashboard updates, outbound HTTP and, without HTTPS, plain-HTTP admin. You open the rest one by one.' ),
			'standard' => __( 'What WordPress ships with. Only your own switches apply.' ),
			'open'     => __( 'Every feature open. Useful for a dev site.' ),
		);
		?>
		<style>
			.hp-wrap { max-width: 800px; margin: 0 auto; }
			.hp-wrap .hp-lead { color: #50575e; margin: 0 0 1.5rem; }
			.hp-postures { display: grid; grid-template-columns: repeat( 3, 1fr ); gap: 12px; margin: 0 0 1.5rem; padding: 0; border: 0; }
			.hp-posture { display: block; background: #fff; border: 1px solid #c3c4c7; border-radius: 4px; padding: 12px 14px; cursor: pointer; }
			.hp-posture:has( input:checked ) { border-color: #2271b1; box-shadow: 0 0 0 1px #2271b1; }
			.hp-posture input { margin: 0 6px 0 0; vertical-align: -1px; }
			.hp-posture strong { display: inline-block; font-size: 14px; }
			.hp-posture span { display: block; margin-top: 4px; color: #646970; font-size: 12px; line-height: 1.4; }
			.hp-summary { display: flex; gap: 1.5rem; align-items: center; margin: 0 0 .75rem; color: #50575e; }
			.hp-summary strong { font-size: 20px; font-weight: 600; color: #1d2327; margin-right: 4px; }
			.hp-head { display: grid; grid-template-columns: 1fr 120px 150px; gap: 12px; padding: 0 16px 6px 20px; color: #646970; font-size: 11px; text-transform: uppercase; letter-spacing: .02em; }
			.hp-dials { background: #fff; border: 1px solid #c3c4c7; border-radius: 4px; }
			.hp-dial { display: grid; grid-template-columns: 1fr 120px 150px; align-items: center; gap: 12px; padding: 12px 16px; border-top: 1px solid #dcdcde; border-left: 4px solid transparent; }
			.hp-dial:first-child { border-top: 0; }
			.hp-dial.is-drift { border-left-color: #d63638; background: #fcf9f9; }
			.hp-dial-name { font-weight: 600; color: #1d2327; }
			.hp-dial-why { margin: 6px 0 0; padding: 6px 8px; background: #f6f7f7; border: 1px solid #dcdcde; border-radius: 3px; color: #50575e; font-size: 12px; line-height: 1.5; }
			.hp-dial-why a { white-space: nowrap; }
			.hp-dial-how { margin-top: 2px; color: #646970; font-size: 12px; }
			.hp-dial-how summary { cursor: pointer; color: #2271b1; }
			.hp-dial-how pre { margin: 6px 0 0; padding: 6px 8px; background: #f6f7f7; border: 1px solid #dcdcde; border-radius: 3px; font-size: 11px; white-space: pre-wrap; }
			.hp-dial-note { margin-top: 4px; color: #996800; font-size: 12px; }
			.hp-state { white-space: nowrap; font-weight: 500; }
			.hp-state .dashicons { font-size: 18px; width: 18px; height: 18px; vertical-align: -4px; }
			.hp-state.is-open { color: #d63638; }
			.hp-state.is-closed { color: #00a32a; }
			.hp-state .hp-pill { display: inline-block; padding: 1px 7px; border-radius: 10px; background: #fcf0f1; color: #8a2424; font-weight: 600; font-size: 11px; margin-left: 4px; vertical-align: 1px; }
			.hp-switch { display: inline-flex; align-items: center; gap: 8px; cursor: pointer; white-space: nowrap; }
			.hp-switch input { position: absolute; opacity: 0; width: 0; height: 0; }
			.hp-switch .hp-track { position: relative; width: 36px; height: 20px; border-radius: 10px; background: #8c8f94; transition: background .15s; flex: none; }
			.hp-switch .hp-track::after { content: ""; position: absolute; top: 2px; left: 2px; width: 16px; height: 16px; border-radius: 50%; background: #fff; transition: transform .15s; }
			.hp-switch input:checked + .hp-track { background: #d63638; }
			.hp-switch input:checked + .hp-track::after { transform: translateX( 16px ); }
			.hp-switch input:focus-visible + .hp-track { box-shadow: 0 0 0 2px #fff, 0 0 0 4px #2271b1; }
			.hp-switch .hp-switch-text { min-width: 44px; font-size: 13px; color: #1d2327; }
			.hp-switch.is-pinned { cursor: default; opacity: .6; }
			.hp-pinned-note { font-size: 11px; color: #646970; white-space: normal; overflow-wrap: anywhere; }
			.hp-pinned-note code { font-size: 10px; padding: 1px 3px; overflow-wrap: break-word; }
			.hp-dial > div { min-width: 0; }
			.hp-wrap p.submit { padding: 1rem 0 0; margin: 0 0 2rem; }
			.hp-notyet { color: #646970; border-top: 1px solid #dcdcde; padding-top: 1rem; }
			.hp-notyet h3 { margin: 0 0 .5rem; font-size: 13px; color: #1d2327; }
			.hp-notyet ul { margin: 0; padding-left: 1.2em; list-style: disc; }
			@media ( max-width: 782px ) {
				.hp-postures { grid-template-columns: 1fr; }
				.hp-head { display: none; }
				.hp-dial { grid-template-columns: 1fr auto; }
				.hp-dial-name { grid-column: 1 / -1; }
			}
		</style>
		<div class="health-check-body hp-wrap hide-if-no-js">
			<?php if ( ! empty( $_GET['saved'] ) ) : ?>
				<div class="notice notice-success inline"><p><?php _e( 'Posture saved.' ); ?></p></div>
			<?php endif; ?>

			<h2><?php _e( 'Hardening posture' ); ?></h2>
			<p class="hp-lead"><?php _e( 'A firewall for features. Pick a posture, then switch individual features open or closed. Anything that stays open although it is switched to closed is reported as drift on the Status tab.' ); ?></p>

			<form method="post" id="hp-form">
				<?php wp_nonce_field( 'hp_save_posture' ); ?>
				<fieldset class="hp-postures">
					<legend class="screen-reader-text"><?php _e( 'Posture' ); ?></legend>
					<?php foreach ( $this->postures() as $key => $label ) : ?>
						<label class="hp-posture">
							<input type="radio" name="hp_posture" value="<?php echo esc_attr( $key ); ?>" <?php checked( $posture, $key ); ?>>
							<strong><?php echo esc_html( preg_replace( '/\s*\(.*\)$/', '', $label ) ); ?></strong>
							<span><?php echo esc_html( $blurbs[ $key ] ); ?></span>
						</label>
					<?php endforeach; ?>
				</fieldset>

				<div class="hp-summary">
					<div><strong><?php echo (int) $open; ?></strong><?php _e( 'open' ); ?></div>
					<div><strong><?php echo count( $dials ) - $open; ?></strong><?php _e( 'closed' ); ?></div>
					<div><strong><?php echo count( $drift ); ?></strong><?php _e( 'drifting' ); ?></div>
				</div>

				<div class="hp-head" aria-hidden="true">
					<span><?php _e( 'Feature' ); ?></span><span><?php _e( 'Right now' ); ?></span><span><?php _e( 'Switch' ); ?></span>
				</div>
				<div class="hp-dials">
				<?php foreach ( $dials as $key => $dial ) :
					$is_open   = $this->effective_open( $key, $dial );
					$wanted    = $this->desired_open( $key, $dial );
					$is_drift  = isset( $drift[ $key ] );
					$is_pinned = $this->pinned( $dial );
					$id        = 'hp-state-' . $key; ?>
					<div class="hp-dial<?php echo $is_drift ? ' is-drift' : ''; ?>">
						<div>
							<div class="hp-dial-name"><?php echo esc_html( $dial['label'] ); ?></div>
							<?php if ( ! empty( $dial['why'] ) ) : ?>
								<div class="hp-dial-how"><details><summary><?php _e( 'What does this protect?' ); ?></summary><p class="hp-dial-why"><?php echo esc_html( $dial['why'] ); ?>
									<?php if ( ! empty( $dial['link'] ) ) : ?>
										<a href="<?php echo esc_url( $dial['link'] ); ?>" target="_blank" rel="noopener"><?php _e( 'Learn more' ); ?><span class="screen-reader-text"> <?php _e( '(opens in a new tab)' ); ?></span></a>
									<?php endif; ?>
								</p></details></div>
							<?php endif; ?>
							<?php if ( ! empty( $dial['fix'] ) ) : ?>
								<div class="hp-dial-how"><details><summary><?php _e( 'Make it permanent in wp-config.php' ); ?></summary><pre><?php echo esc_html( $dial['fix'] ); ?></pre></details></div>
							<?php endif; ?>
							<?php if ( ! empty( $dial['note'] ) ) : ?>
								<div class="hp-dial-note"><?php echo esc_html( $dial['note'] ); ?></div>
							<?php endif; ?>
						</div>
						<div class="hp-state <?php echo $is_open ? 'is-open' : 'is-closed'; ?>">
							<span class="dashicons <?php echo $is_open ? 'dashicons-warning' : 'dashicons-yes-alt'; ?>"></span>
							<?php echo $is_open ? __( 'Open' ) : __( 'Closed' ); ?>
							<?php if ( $is_drift ) : ?><span class="hp-pill"><?php _e( 'drift' ); ?></span><?php endif; ?>
						</div>
						<div>
							<label class="hp-switch<?php echo $is_pinned ? ' is-pinned' : ''; ?>" for="<?php echo esc_attr( $id ); ?>">
								<input type="checkbox" id="<?php echo esc_attr( $id ); ?>" name="hp_state[<?php echo esc_attr( $key ); ?>]" value="1" <?php checked( $wanted ); ?> <?php disabled( $is_pinned ); ?> data-open="<?php esc_attr_e( 'Open' ); ?>" data-closed="<?php esc_attr_e( 'Closed' ); ?>"<?php
									foreach ( array_keys( $this->postures() ) as $p ) {
										printf( ' data-default-%s="%s"', esc_attr( $p ), $this->posture_default_open( $key, $dial, $p ) ? '1' : '0' );
									}
								?>>
								<span class="hp-track" aria-hidden="true"></span>
								<span class="hp-switch-text"><?php echo $wanted ? __( 'Open' ) : __( 'Closed' ); ?></span>
							</label>
							<input type="hidden" name="hp_rendered[<?php echo esc_attr( $key ); ?>]" value="<?php echo $wanted ? '1' : '0'; ?>">
							<?php if ( $is_pinned ) : ?>
								<div class="hp-pinned-note"><?php printf( __( 'Set by %s in wp-config.php' ), '<code>' . str_replace( '_', '_<wbr>', esc_html( $dial['constant'] ) ) . '</code>' ); ?></div>
							<?php endif; ?>
						</div>
					</div>
				<?php endforeach; ?>
				</div>
				<p class="submit"><button type="submit" name="hp_save" value="1" class="button button-primary"><?php _e( 'Save posture' ); ?></button></p>
			</form>

			<div class="hp-notyet">
				<h3><?php _e( 'Not in this prototype yet' ); ?></h3>
				<ul>
					<li><?php _e( 'Running at install time, so the constants land in wp-config.php while the installer still owns that file.' ); ?></li>
					<li><?php _e( 'History, so the dashboard can say what changed since the last weekly run.' ); ?></li>
					<li><?php _e( 'An export of host-level items for the hosting provider.' ); ?></li>
				</ul>
			</div>
		</div>
		<script>
			( function () {
				var boxes = document.querySelectorAll( '#hp-form .hp-switch input[type="checkbox"]' );
				function label( box ) {
					box.closest( '.hp-switch' ).querySelector( '.hp-switch-text' ).textContent = box.checked ? box.dataset.open : box.dataset.closed;
				}
				boxes.forEach( function ( box ) {
					box.addEventListener( 'change', function () { label( box ); } );
				} );
				// Picking a posture card previews that posture: every switch you have not
				// touched moves to the posture's default. Pinned switches stay put.
				document.querySelectorAll( '#hp-form input[name="hp_posture"]' ).forEach( function ( radio ) {
					radio.addEventListener( 'change', function () {
						boxes.forEach( function ( box ) {
							var value = box.dataset[ 'default' + radio.value.charAt( 0 ).toUpperCase() + radio.value.slice( 1 ) ];
							if ( box.disabled || typeof value === 'undefined' ) {
								return;
							}
							box.checked = '1' === value;
							label( box );
						} );
					} );
				} );
			} )();
		</script>
		<?php
	}
}

HP_Prototype::boot();
