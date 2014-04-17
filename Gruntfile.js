module.exports = function(grunt) {
    'use strict';

    // Project configuration.
    grunt.initConfig({
        jshint: {
            all: ['*.js', 'src/*.js', 'test/*.js'],
            options: {
                jshintrc: '.jshintrc'
            }
        },

        mochaTest: {
            all: {
                options: {
                    reporter: 'spec'
                },
                src: ['test/unit-test.js', 'test/integration-test.js']
            }
        },

        connect: {
            test: {
                options: {
                    port: 8123,
                    base: '.'
                }
            },
            dev: {
                options: {
                    port: 8124,
                    base: '.',
                    keepalive: true
                }
            }
        },

        mocha_phantomjs: {
            all: {
                options: {
                    reporter: 'spec',
                    urls: ['http://localhost:8123/test/unit.html']
                }
            }
        }
    });

    // Load the plugin(s)
    grunt.loadNpmTasks('grunt-contrib-jshint');
    grunt.loadNpmTasks('grunt-mocha-test');
    grunt.loadNpmTasks('grunt-mocha-phantomjs');
    grunt.loadNpmTasks('grunt-contrib-connect');

    // Tasks
    grunt.registerTask('dev', ['connect:dev']);
    grunt.registerTask('default', ['jshint', 'mochaTest', 'connect:test', 'mocha_phantomjs']);
};