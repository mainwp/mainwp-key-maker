<?php
/*
	Plugin Name: MainWP Key Maker
	Plugin URI: https://mainwp.com/
	Description: Easily convert a form into a "key" to use with the MainWP Bulk Settings Manager Extension
	Author: MainWP
	Author URI: https://mainwp.com
	Version: 0.2
 */

// If we made redirection in this session
$mainwp_key_maker_is_redirect = false;
// Store current user session id
$mainwp_key_maker_session_id = "";


if ( ! function_exists( "mainwp_key_maker_get_session_id" ) ) {
	/**
	 * Get current user session id
	 */
	function mainwp_key_maker_get_session_id() {
		global $mainwp_key_maker_session_id;

		// We use global so this happen only once		
		if (empty($mainwp_key_maker_session_id)) {
			if ( defined( "AUTH_COOKIE" ) && isset( $_COOKIE[ AUTH_COOKIE ] )) {
				// Different users can share one account - so use session id
				$cookie_elements = explode( '|', $_COOKIE[ AUTH_COOKIE ] );
				if ( isset( $cookie_elements[2] ) ) {
					$mainwp_key_maker_session_id = substr( (string) $cookie_elements[2], 0, 30 );
				}
			} else if ( defined( "SECURE_AUTH_COOKIE" ) && isset( $_COOKIE[ SECURE_AUTH_COOKIE ] )) {
				// Different users can share one account - so use session id
				$cookie_elements = explode( '|', $_COOKIE[ SECURE_AUTH_COOKIE ] );
				if ( isset( $cookie_elements[2] ) ) {
					$mainwp_key_maker_session_id = substr( (string) $cookie_elements[2], 0, 30 );
				}				
			}
		}
	}
}


if ( ! function_exists( "mainwp_key_maker_store_request" ) ) {
	/**
	 * Store $_GET/$_POST inside transient for further use
	 */
	function mainwp_key_maker_store_request() {
		global $mainwp_key_maker_session_id, $mainwp_key_maker_is_redirect;

		mainwp_key_maker_get_session_id();

		// Only for logged
		if ( ! empty( $mainwp_key_maker_session_id ) ) {
			// Skip heartbleeed WordPress action
			if ( isset( $_REQUEST['action'] ) && $_REQUEST['action'] == 'heartbeat' && isset( $_REQUEST['screen_id'] ) ) {
				return;
			}

			$previous_data = get_transient( 'mainwp_eir_' . $mainwp_key_maker_session_id );
			if ( $previous_data === false ) {
				$previous_data = array();
			}

			$datas = array();

			// Store values in transient so we have access to them in next page
			$datas['post'] = $_POST;
			$datas['get']  = $_GET;
			$datas['url']  = 'http://' . $_SERVER['HTTP_HOST'] . $_SERVER['PHP_SELF'];
			$datas['time'] = time();

			$previous_data[] = $datas;

			set_transient( 'mainwp_eir_' . $mainwp_key_maker_session_id, $previous_data, 90 );
			$mainwp_key_maker_is_redirect = true;
		}
	}
}

// We add additional functionality to wp_redirect and wp_verify_nonce for administrators
if ( ! function_exists( 'wp_redirect' ) ) :

	/**
	 * Redirects to another page.
	 * Additionally, stores $_GET, $_POST and url in transient
	 *
	 * @since 1.5.1
	 *
	 * @global bool $is_IIS
	 *
	 * @param string $location The path to redirect to.
	 * @param int $status Status code to use.
	 *
	 * @return bool False if $location is not provided, true otherwise.
	 */
	function wp_redirect( $location, $status = 302 ) {
		global $is_IIS;

		/**
		 * Filter the redirect location.
		 *
		 * @since 2.1.0
		 *
		 * @param string $location The path to redirect to.
		 * @param int $status Status code to use.
		 */
		$location = apply_filters( 'wp_redirect', $location, $status );

		/**
		 * Filter the redirect status code.
		 *
		 * @since 2.3.0
		 *
		 * @param int $status Status code to use.
		 * @param string $location The path to redirect to.
		 */
		$status = apply_filters( 'wp_redirect_status', $status, $location );

		if ( ! $location ) {
			return false;
		}

		$location = wp_sanitize_redirect( $location );

		if ( ! $is_IIS && PHP_SAPI != 'cgi-fcgi' ) {
			status_header( $status );
		} // This causes problems on IIS and some FastCGI setups

		mainwp_key_maker_store_request();

		header( "Location: $location", true, $status );

		return true;
	}
endif;

if ( ! function_exists( 'wp_verify_nonce' ) ) :
	/**
	 * Verify that correct nonce was used with time limit.
	 * Additionally stores name of nonce action in transient
	 *
	 * The user is given an amount of time to use the token, so therefore, since the
	 * UID and $action remain the same, the independent variable is the time.
	 *
	 * @since 2.0.3
	 *
	 * @param string $nonce Nonce that was used in the form to verify
	 * @param string|int $action Should give context to what is taking place and be the same when nonce was created.
	 *
	 * @return false|int False if the nonce is invalid, 1 if the nonce is valid and generated between
	 *                   0-12 hours ago, 2 if the nonce is valid and generated between 12-24 hours ago.
	 */
	function wp_verify_nonce( $nonce, $action = - 1 ) {
		global $mainwp_key_maker_session_id;

		if ( ! empty( $mainwp_key_maker_session_id ) ) {
			$key_maker = get_transient( 'mainwp_ein_' . $mainwp_key_maker_session_id );
			if ( $key_maker === false ) {
				$key_maker = array();
			}

			$key_maker[ trim( $nonce ) ] = $action;
			set_transient( 'mainwp_ein_' . $mainwp_key_maker_session_id, $key_maker );
		}

		$nonce = (string) $nonce;
		$user  = wp_get_current_user();
		$uid   = (int) $user->ID;
		if ( ! $uid ) {
			/**
			 * Filter whether the user who generated the nonce is logged out.
			 *
			 * @since 3.5.0
			 *
			 * @param int $uid ID of the nonce-owning user.
			 * @param string $action The nonce action.
			 */
			$uid = apply_filters( 'nonce_user_logged_out', $uid, $action );
		}

		if ( empty( $nonce ) ) {
			return false;
		}

		$token = wp_get_session_token();
		$i     = wp_nonce_tick();

		// Nonce generated 0-12 hours ago
		$expected = substr( wp_hash( $i . '|' . $action . '|' . $uid . '|' . $token, 'nonce' ), - 12, 10 );
		if ( hash_equals( $expected, $nonce ) ) {
			return 1;
		}

		// Nonce generated 12-24 hours ago
		$expected = substr( wp_hash( ( $i - 1 ) . '|' . $action . '|' . $uid . '|' . $token, 'nonce' ), - 12, 10 );
		if ( hash_equals( $expected, $nonce ) ) {
			return 2;
		}

		// Invalid nonce
		return false;
	}
endif;

if ( defined( 'DOING_AJAX' ) && DOING_AJAX ) {
	// We want to support ajax calls also
	mainwp_key_maker_store_request();
}

class MainWP_Key_Maker {

	public function __construct() {
		add_action( 'init', array( $this, 'init' ) );
	}

	public function init() {
		mainwp_key_maker_get_session_id();

		if ( ! current_user_can( 'manage_options' ) || ! is_admin() ) {
			return;
		}

		global $mainwp_key_maker_is_redirect;

		// Display redirect data on next page
		if ( $mainwp_key_maker_is_redirect ) {
			return;
		}

		// Skip Ajax
		if ( defined( 'XMLRPC_REQUEST' ) || defined( 'DOING_AJAX' ) || defined( 'IFRAME_REQUEST' ) ) {
			return;
		}

		// Don't process if fatal error
		$error = error_get_last();
		if ( ! empty( $error ) && ( $error['type'] & ( E_ERROR | E_USER_ERROR | E_RECOVERABLE_ERROR ) ) ) {
			return;
		}

		add_action( 'wp_before_admin_bar_render', array( $this, 'bar_render' ), 999 );
		add_action( 'admin_footer', array( $this, 'toolbar' ), 999 );
	}

	/**
	 * Render Key Maker button inside admin bar
	 * Display content using thickbox popup
	 */
	public function bar_render() {
		global $wp_admin_bar;

		wp_register_script( 'mainwp-key-maker-colorbox', plugins_url( '/js/jquery.colorbox-min.js', __FILE__ ), array( 'jquery' ) );
		wp_enqueue_script( 'mainwp-key-maker-colorbox' );

		wp_register_script( 'mainwp-key-maker-zeroclipboard', plugins_url( '/js/ZeroClipboard.min.js', __FILE__ ), array( 'jquery' ) );
		wp_enqueue_script( 'mainwp-key-maker-zeroclipboard' );

		wp_register_style( 'mainwp-key-maker-colorbox', plugins_url( '/css/colorbox.css', __FILE__ ) );
		wp_enqueue_style( 'mainwp-key-maker-colorbox' );

		$args = array(
			'id'    => 'mainwp-key-maker-adminbar-node',
			'title' => __( 'MainWP Key Maker', 'mainwp-key-maker' ),
			'href'  => '#mainwp-key-maker-box'
		);

		$wp_admin_bar->add_node( $args );
		?>
		<style>
			#wp-admin-bar-mainwp-key-maker {
				cursor: pointer;
			}
			.mainwp-km-info {
				margin-top: 1em;
				padding: .6em;
				border-left: 4px Solid #7fb100;
				box-shadow: 0 1px 1px 0 rgba(0,0,0,.1);
				-webkit-box-shadow: 0 1px 1px 0 rgba(0,0,0,.1);
			}
		</style>
		<script>
			jQuery(function () {
				ZeroClipboard.config( { swfPath: "<?php echo plugins_url( '/js/ZeroClipboard.swf', __FILE__ ); ?>" } );

				var client = new ZeroClipboard(jQuery(".mainwp-key-maker-textarea"));

				client.on('ready', function (event) {
					client.on("copy", function (event) {
						event.clipboardData.setData("text/plain", event.target.innerHTML);
					});

					client.on('aftercopy', function (event) {
						jQuery("#" + event.target.id + "-button").val('<?php _e('Copied to Clipboard!', 'mainwp-key-maker'); ?>');
						jQuery("#" + event.target.id + "-button").removeClass('button-primary');
						setInterval(function () {
							jQuery("#" + event.target.id + "-button").val('<?php _e('Copy to Clipboard', 'mainwp-key-maker'); ?>');
							jQuery("#" + event.target.id + "-button").addClass('button-primary');
						}, 3000);
					});
				});

				var client2 = new ZeroClipboard(jQuery(".mainwp-key-maker-copy-button"));

				client2.on('ready', function (event) {
					client2.on('aftercopy', function (event) {
						event.target.value = '<?php _e('Copied to Clipboard!', 'mainwp-key-maker'); ?>';
						event.target.classList.remove('button-primary');
						setInterval(function () {
							event.target.value = '<?php _e('Copy to Clipboard', 'mainwp-key-maker'); ?>';
							event.target.classList.add('button-primary');
						}, 3000);
					});
				});

				jQuery("#wp-admin-bar-mainwp-key-maker-adminbar-node a").colorbox({inline: true, width: "1230px"});

				jQuery(".mainwp-key-maker-debug-a").on("click", function () {
					jQuery("#mainwp-key-maker-debug-" + jQuery(this).attr("ids")).toggle();
				});
			});
		</script>

		<?php
	}

	/**
	 * Display content for admin bar button
	 */
	public function toolbar() {
		global $mainwp_key_maker_session_id;

		// Do we have anything to display?
		$is_any_info = false;
		$is_there_pre_request = false;
		?>
		<div style="display:none;">
			<div id="mainwp-key-maker-box">
				<span style="float: right;">
					<a href="https://mainwp.com" target="_blank" title="MainWP"><img style="height: 40px; margin-right: 15px;" src="<?php echo plugins_url('images/logo.png', __FILE__); ?>" alt="MainWP" /></a>
				</span>
				<h1><?php _e( 'MainWP Key Maker', 'mainwp-key-maker'); ?></h1>
				<div style="clear: both;"></div>
				<?php

				$nonce = get_transient( 'mainwp_ein_' . $mainwp_key_maker_session_id );

				if ( $nonce === false ) {
					$nonce = array();
				}

				$previous_datas = get_transient( 'mainwp_eir_' . $mainwp_key_maker_session_id );

				if ( $previous_datas !== false ) {
					delete_transient( 'mainwp_ein_' . $mainwp_key_maker_session_id );
					delete_transient( 'mainwp_eir_' . $mainwp_key_maker_session_id );
					foreach ( $previous_datas as $previous_counter => $previous_data ):
						if ( ( isset( $previous_data['post'] ) && ! empty( $previous_data['post'] ) ) || ( isset( $previous_data['get'] ) && ! empty( $previous_data['get'] ) ) ):
							$is_any_info = true;
							$is_there_pre_request = true;
							?>
							<div style="padding-bottom: 1em; margin-bottom: 1px Solid #000;">
								<?php
								if ( $is_there_pre_request ):
									?>
									<div class="mainwp-km-info">
										<em><?php _e('The "Verify Form Fields and Values" button allows you to tell if the Key will contain the information you want.', 'mainwp-key-maker'); ?></em><br/>
										<em><?php _e('If it does not, you may need to submit the form in order for the Key Maker to be able to correctly gather the form fields and values.', 'mainwp-key-maker'); ?></em>
									</div>
									<?php
								endif;
								?>
								<p>
								<h2 style="margin-bottom: .3em;"><?php _e( 'Post-submission Request', 'mainwp-key-maker' ); ?></h2>
									<em>( <?php echo date_i18n( "d-m-Y H:i:s", $previous_data['time'] ); ?> )</em>
									<?php echo( isset( $previous_data['url'] ) ? esc_html( $previous_data['url'] ) : __( 'Unknown url', 'mainwp-key-maker' ) ); ?>
									<span style="float: right; margin-right: 1.5em;">
										<a href="#"
										   class="mainwp-key-maker-debug-a button"
										   style="text-decoration: none;"
										   ids="<?php echo esc_attr( $previous_counter ); ?>"><?php _e( 'Verify Form Fields and Values', 'mainwp-key-maker' ); ?>
										</a>
										<input type="submit"
											   id="mainwp-key-maker-textarea-previous-<?php echo esc_attr( $previous_counter ); ?>-button"
											   data-clipboard-target="mainwp-key-maker-textarea-previous-<?php echo esc_attr( $previous_counter ); ?>"
											   class="mainwp-key-maker-copy-button button button-primary"
											   value="<?php _e( 'Copy to Clipboard', 'mainwp-key-maker' ); ?>">
									</span>
								</p>
								<div id="mainwp-key-maker-debug-<?php echo esc_attr( $previous_counter ); ?>"
								     style="display:none; width: 1170px !important; margin-bottom: 1em;"
								     class="postbox">
									<div class="inside">
										<pre><?php echo $this->custom_print_r( $previous_data, $nonce ); ?></pre>
									</div>
								</div>

								<textarea rows="12"
								          cols="90"
								          style="width: 1170px;"
								          class="mainwp-key-maker-textarea"
								          id="mainwp-key-maker-textarea-previous-<?php echo esc_attr( $previous_counter ); ?>"
								          readonly><?php echo esc_textarea( $this->parse_data( $previous_data, $nonce ) ); ?></textarea>
							</div>
							<?php
						endif;
					endforeach;


				}

				$current_data         = array();
				$current_data['post'] = $_POST;
				$current_data['get']  = $_GET;
				$current_data['url']  = 'http://' . $_SERVER['HTTP_HOST'] . $_SERVER['PHP_SELF'];
				$current_data['time'] = time();
				?>
				<div style="padding-bottom: 1em; margin-bottom: 1px Solid #000;">
					<?php
					if (!empty($current_data['post']) || !empty($current_data['get'])):
						$is_any_info = true;
					?>
						<?php
							if ( ! $is_there_pre_request ):
								?>
								<div class="mainwp-km-info">
									<em><?php _e('The "Verify Form Fields and Values" button allows you to tell if the Key will contain the information you want.', 'mainwp-key-maker'); ?></em><br/>
									<em><?php _e('If it does not, you may need to submit the form in order for the Key Maker to be able to correctly gather the form fields and values.', 'mainwp-key-maker'); ?></em>
								</div>
								<?php
							endif;
						?>
						<p>
						<h2 style="margin-bottom: .3em;"><?php _e('Pre-submission Request', 'mainwp-key-maker'); ?></h2>
						<em>( <?php echo date_i18n("d-m-Y H:i:s", $current_data['time']); ?> )</em>
						<?php echo esc_html($current_data['url']); ?>
							<span style="float: right; margin-right: 1.5em;">
							  <a
									href="#"
									class="mainwp-key-maker-debug-a button"
									ids="current"
									style="text-decoration: none;"><?php _e('Verify Form Fields and Values', 'mainwp-key-maker'); ?>
								</a>
								<input type="submit"
									   id="mainwp-key-maker-textarea-button"
									   data-clipboard-target="mainwp-key-maker-textarea"
									   class="mainwp-key-maker-copy-button button button-primary"
									   value="<?php _e('Copy to clipboard', 'mainwp-key-maker'); ?>">
							</span>
						</p>

						<div id="mainwp-key-maker-debug-current"
							 style="display:none; width: 1170px !important; margin-bottom: 1em;"
							 class="postbox">
							<div class="inside">
								<pre><?php echo $this->custom_print_r($current_data, $nonce); ?></pre>
							</div>
						</div>


						<textarea rows="12"
								  cols="90"
								  style="width: 1170px;"
								  class="mainwp-key-maker-textarea"
								  id="mainwp-key-maker-textarea"
								  readonly><?php echo esc_textarea($this->parse_data($current_data, $nonce)); ?></textarea>
					<?php
					endif;

					if ( ! $is_any_info ):
						?>
						<div class="mainwp-km-info"><?php _e( 'No form detected. You may have to submit the form before Key Maker is able to find the form and make the Key.', 'mainwp-key-maker' ); ?></div>
						<?php
					endif;
					?>
				</div>
			</div>
		</div>
		<?php
	}

	/**
	 * @param $data
	 * @param $nonce
	 *
	 * Print $_GET and $_POST using print_r with XSS protection
	 *
	 * @return string
	 */
	public function custom_print_r( $data, $nonce ) {
		return esc_html( print_r( $this->check_nonces( $data, $nonce ), true ) );
	}

	/**
	 * @param $data
	 * @param $nonce
	 *
	 * Recursive check if in array, nonce field exist
	 *
	 * @return array
	 */
	public function check_nonces( $data, $nonce ) {
		$new = array();
		foreach ( $data as $key => $val ) {
			if ( is_array( $val ) ) {
				$new[ $key ] = $this->check_nonces( $val, $nonce );
			} else {
				$val = trim( $val );
				if ( isset( $nonce[ $val ] ) ) {
					$new[ $key ] = __( 'NONCE FIELD', 'mainwp-key-maker' ) . ' - ' . $nonce[ $val ];
				} else {
					$new[ $key ] = $val;
				}
			}
		}

		return $new;
	}

	/**
	 * @param $data
	 * @param $nonce
	 *
	 * Parse datas in format readable for Skeleton Key
	 *
	 * @return string
	 */
	public function parse_data( $data, $nonce ) {
		$out = array();
		if ( isset( $data['post'] ) ) {
			foreach ( $this->flatten_array( $data['post'] ) as $key => $val ) {
				$array = array();
				$val   = trim( $val );

				if ( isset( $nonce[ $val ] ) ) {
					$array['field_type']       = 'nonce_field';
					$array['nonce_field_name'] = $nonce[ $val ];
					$array['nonce_field_arg']  = $key;
				} else {
					if ( strpos( $val, "\n" ) !== false || strpos( $val, "\r" ) !== false ) {
						$array['field_type']                 = 'textarea_field';
						$array['textarea_field_description'] = $val;
						$array['textarea_field_name']        = $key;
						$array['textarea_field_value']       = $val;
						$array['textarea_field_type']        = 'post';
					} else {
						$array['field_type']             = 'text_field';
						$array['text_field_description'] = $val;
						$array['text_field_name']        = $key;
						$array['text_field_value']       = $val;
						$array['text_field_type']        = 'post';
					}
				}

				$out[] = http_build_query( $array );
			}
		}

		if ( isset( $data['get'] ) ) {
			foreach ( $this->flatten_array( $data['get'] ) as $key => $val ) {
				$array = array();
				$val   = trim( $val );

				if ( isset( $nonce[ $val ] ) ) {
					$array['field_type']       = 'nonce_field';
					$array['nonce_field_name'] = $nonce[ $val ];
					$array['nonce_field_arg']  = $key;
				} else {
					$array['field_type']             = 'text_field';
					$array['text_field_description'] = $val;
					$array['text_field_name']        = $key;
					$array['text_field_value']       = $val;
					$array['text_field_type']        = 'get';
				}

				$out[] = http_build_query( $array );
			}
		}

		$url = "";
		if ( isset( $data['url'] ) ) {
			$url = parse_url( $data['url'] );
			$url = ( isset( $url['path'] ) ? $url['path'] : '' ) . ( isset( $url['query'] ) ? '?' . $url['query'] : '' );
		}

		$array                        = array();
		$array['field_type']          = 'settings_field';
		$array['settings_field_name'] = __( 'Imported', 'mainwp-key-maker' ) . ' ' . current_time( "d-m-Y H:i:s" );
		$array['settings_field_url']  = $url;

		$content = http_build_query( $array ) . '&' . implode( '&', $out );
		$hash    = sha1( $content );

		$return = "-----BEGIN BULK SETTINGS MANAGER KEY-----\r\n";
		$return .= base64_encode( $hash . '|' . $content );
		$return .= "\r\n-----END BULK SETTINGS MANAGER KEY-----\r\n";

		return $return;
	}

	/**
	 * @param $array
	 * @param string $previous
	 *
	 * Convert multidimensional array into single dimensional array
	 * Something like http[like][array][structure]
	 *
	 * @return array
	 */
	public function flatten_array( $array, $previous = "" ) {
		$out = array();
		foreach ( $array as $key => $val ) {
			if ( is_array( $val ) ) {
				$out = array_merge( $this->flatten_array( $val, ( $previous == "" ? $key : $previous . '[' . $key . ']' ) ), $out );
			} else {
				if ( $previous == "" ) {
					$out[ $key ] = $val;
				} else {
					$out[ $previous . '[' . $key . ']' ] = $val;
				}
			}
		}

		return $out;
	}
}

$mainWP = new MainWP_Key_Maker();